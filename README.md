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
cargo xtask tempo                    # a hora pela rede: fontes de Roughtime no hospedeiro
cargo xtask mainnet --release        # a rede principal do IC, de verdade: à mão, fora da CI
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
| `admin.execute` | Uma operação administrativa com a prova de um administrador (`challenge`, `command`, `params`, `admin`, `proof`): `agent.register`, `agent.revoke`, `policy.assign`, `policy.write`, `person.register`, `person.revoke`, `credential.rotate`, `session.revoke`, `lease.revoke`, `message.send`, `message.read`, `message.ack`, `message.purge`, `message.purge_mailbox`, `time.confirm` — o salto de hora pendente, sem hora digitada —, `key.revoke` — anula a chave de assinatura de outra identidade, sem dar o uso dela a ninguém —; e, com as assinaturas de um quórum em `signatures`, `admin.revoke` |
| `audit.tail` | Os registros mais recentes da auditoria encadeada, com o que basta para refazer cada elo, e quais já estão no journal; com `after`, os seguintes a um número, do mais velho ao mais novo — a leitura de quem acompanha a cadeia (`count`, `after`) |
| `audit.head` | A cabeça da auditoria — o elo do último registro, para ancorar fora da máquina —, a âncora e quantos há |
| `audit.verify` | Refaz a cadeia guardada a partir da âncora e diz se cada elo confere |
| `audit.declare` | Declara um fato de quem pede para a auditoria — uma alegação, e não um fato do kernel: o evento, o assunto e o desfecho vão, como vieram, no recurso de um registro da cadeia; quem, o papel, a sessão, o processo, o programa e a decisão, no detalhe, pelo kernel. Ancorada numa conexão de quem declara, o detalhe leva o destino real dela, pela tabela da pilha; a de outro titular, ou uma que não existe, é `INVALID_ARGUMENT`, sem dizer de quem é. Ancorada numa decisão, o detalhe leva o número e o método dela, que tem de ser um `ALLOW` de quem declara e do mesmo processo — a assinatura de um `key.sign` —; uma de outro, ou outra declaração, é `INVALID_ARGUMENT`. Uma âncora só. Nenhuma decisão lê uma declaração. Exige `audit.declare`, e gasta a taxa do papel (`event`, `subject`, `outcome`, `connection`, `decision`) |
| `key.create` | Cria uma chave de assinatura Ed25519 da identidade de quem pede — a pessoa, o agente —, num domínio do registro de domínios que o papel usa. A privada nasce do gerador do kernel e nunca sai dele; o nome, `chave:<nome>`, é do espaço da identidade de quem pede, e um nome já usado — por uma chave viva ou destruída — não volta. A chave vai para o journal cifrado antes da resposta, com a decisão no mesmo registro, e volta a cada boot; sem persistência, nenhuma nasce. Devolve a chave pública (`key`, `domain`) |
| `key.read` | O que é público de uma chave de quem pede: a pública, a impressão, o algoritmo, o domínio, a custódia e o estado. Nunca a privada; um nome sem chave para quem pede responde o mesmo que um nome de outro (`key`) |
| `key.sign` | Assina, com uma chave viva de quem pede, um resumo de exatamente 32 bytes no domínio dela — o prefixo registrado do domínio seguido do resumo. Uma decisão por assinatura; no commit, tudo de novo — autoridade, contenção, domínio, chave —, e o registro vai para a auditoria e para o journal antes de a assinatura sair: sem persistência, nada se assina (`key`, `domain`, `digest`) |
| `key.destroy` | Destrói uma chave de quem pede: a privada é apagada, e o nome fica marcado para sempre. A lápide vai para o journal: o boot não traz a chave de volta, e uma fotografia velha do disco é recusada (`key`) |
| `policy.show` | A política em vigor: papéis, permissões, recursos, taxas, o papel da serial e se veio do disco |
| `security.status` | O tecido de segurança: o papel com que o gate decide as leituras dele, até onde leu, o que perdeu, o que pediu e os incidentes |
| `security.incidents` | Os incidentes; com `id`, um inteiro: atores, detecções, registros, recursos, evidência, risco, estado e ações — cada ação com o pedido, o nível, a decisão do gate e quem a autorizou (`id`) |
| `security.events` | A linha do tempo de segurança, de uma identidade, de um incidente ou toda (`principal`, `incident`, `max`) |
| `security.explain` | A interpretação de uma decisão gravada — o que o código quer dizer, a cadeia, o DNS que precedeu uma conexão —, nunca uma segunda decisão (`seq`) |
| `security.provenance` | A cadeia de um processo até a identidade que a começou, os filhos, e a rede dele: cada conexão, a decisão do gate, o DNS e a regra do firewall (`process`, `boot`) |
| `security.risk` | O risco de uma identidade, com os fatores; o perfil de comportamento; e o raio do que ela já tocou (`principal`) |
| `security.verify` | Refaz a cadeia do cofre de evidências |
| `security.metrics` | O custo e o efeito da segurança, medidos desde o boot: as decisões do gate por código e a latência dele, a da política e a da auditoria, as voltas do NSF e o tempo de máquina delas, a memória e as contas do motor (falsos positivos, contenções desfeitas, recusas repetidas), a latência da resposta, os arrendamentos soltos por causa, a conferência do código de fora da imagem, e o orçamento: as decisões de controle, de dados e de fecho, as recusas por taxa, as esperas pelo caminho da auditoria e o atraso dela, a vazão do plano de dados e a justiça entre os principais |
| `system.info` | Kernel, CPU, vídeo, uptime, o RTC, o tempo — `time`: o estado e as marcas do relógio civil, o civil, o lógico, a incerteza, o salto pendente, as fontes, as rodadas e a régua; ver [O tempo](#o-tempo) — e mecanismo de guarda da pilha |
| `system.uptime` | Ticks do timer e milissegundos desde o boot |
| `random.read` | Bytes do gerador do kernel, em hexadecimal, para quem precisa de uma chave — a semente de cada conexão TLS de um programa. De 1 a 256 — fora disso é erro, e não um corte —; sem fonte de entropia, `ENTROPY_UNAVAILABLE` e nenhum byte. A auditoria grava a decisão, nunca os bytes (`bytes`) |
| `time.request` | O pedido do Roughtime — versão 1, 1 KiB, em base64 em `request` — para uma fonte do registro de fontes de hora, `/etc/duke/tempo`, e o `id` dele. O kernel escolhe o nonce — o primeiro do gerador; os seguintes, encadeados à última resposta aceita da rodada — e liga o pedido ao principal que o gate decidiu, à fonte e à chave fixada dela; não escolhe a hora. A rodada começa pela primeira fonte do registro e segue a ordem dele, e pedir de novo a fonte em curso substitui o pedido. Exige `time.sync`; o transporte até a fonte é um `net.connect` UDP, decidido à parte. Uma fonte fora do registro, ou fora da ordem, é `INVALID_REQUEST`; a tabela cheia, `DENY_QUOTA`; sem entropia, `ENTROPY_UNAVAILABLE` (`source`) |
| `time.sync` | Entrega a resposta que chegou de uma fonte de hora — inteira, como chegou, no anexo; sem anexo, o aviso de que ela não veio — para o pedido `id` de quem entrega. O kernel a confere contra o pedido que ele emitiu — o nonce, a chave fixada da fonte, a folha do pacote —, nunca contra o que quem entrega diz. Uma resposta recusada não consome o id (até 4 entregas); a primeira aceita consome; depois de 2 s, o id vence. Na última fonte, a rodada fecha: só o acordo de pelo menos duas chaves do registro move o relógio civil, pelas regras da disciplina, e `round` diz o desfecho. Exige `time.sync`; um id que não é de quem entrega não existe para ele: `INVALID_REQUEST` (`id`, `attachment`) |
| `memory.stats` | Totais agregados de memória física |
| `memory.regions` | Regiões do mapa de memória (`limit`, `usable_only`) |
| `memory.frames` | Estado do alocador de frames físicos |
| `paging.translate` | Traduz um endereço virtual para físico (`address`) |
| `heap.stats` | Estado do heap, incluindo fragmentação e o pico desde o boot (`peak_bytes`) |
| `tasks.stats` | Escalonador cooperativo e fila de entrada do canal |
| `threads.stats` | Escalonador preemptivo: trocas de contexto e quanta |
| `threads.list` | Fios de execução do kernel, com estado e vezes escalonado |
| `user.run` | Lança um programa no anel sem privilégio (`path`; padrão: o exemplo). O código de fora da imagem só roda com o selo de um editor em que o papel confia: senão, `CODE_UNSIGNED`, `CODE_TAMPERED` ou `CODE_UNTRUSTED` |
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
| `net.info` | A placa de rede e a pilha IP: endereço físico, contadores, o endereço e o roteador que o DHCP deu, as conexões, e os datagramas de outra origem descartados |
| `net.arp` | Pergunta quem atende por um IPv4 e espera a resposta (`ip`, `from`) |
| `net.connect` | Abre uma conexão de saída para um destino no alcance do papel: TCP, ou uma associação UDP que só conversa com aquele destino (`to`: `tcp:<ipv4>:<porta>` ou `udp:<ipv4>:<porta>`) |
| `net.send` | Manda bytes por uma conexão sua — texto em `content` ou o anexo, até o buffer da conexão (16 KiB); numa UDP, um datagrama inteiro de até 1472 bytes, ou nada e o motivo; com `wait`, sem espaço na fila de saída, espera a pilha abrir espaço — ou o estado mudar — até o prazo, e a entrega é decidida de novo pelo gate (`connection`, `content`, `attachment`, `wait`) |
| `net.recv` | O que chegou numa conexão sua, até `max` e no máximo o buffer da conexão (16 KiB), e o estado dela; numa UDP, um datagrama inteiro, com o tamanho em `datagram`, e o que não cabe em `max` fica; com `wait`, sem nada chegado, espera a pilha ter o que dizer — o dado, o estado, o fim da conexão — até o prazo; texto em `utf-8` ou `base64` (`connection`, `max`, `wait`) |
| `net.close` | Fecha uma conexão sua (`connection`) |
| `net.observe` | Os datagramas trocados com um destino observado — o conteúdo, em base64, com o dono, o sentido e o último registro da auditoria quando foi guardado (`after_record`, a ordem dele entre as decisões do gate) —, de associações de qualquer titular; só de um destino que um papel tem em `net.observe` (`to`, `after`, `max`) |
| `net.block` | Barra o tráfego para um destino, para todos ou para um dono — e derruba as conexões vivas que a regra alcança. Só restringe (`to`, `owner`) |
| `net.unblock` | Tira a regra de um destino e um dono; o gate continua decidindo cada pedido (`to`, `owner`) |
| `net.rules` | As regras do firewall — o destino, o dono, a decisão que pôs cada uma e quem pediu — e os quadros descartados, em cada sentido: sem fluxo, de fluxo barrado, de protocolo que não passa |
| `process.isolate` | Isola um processo: ele continua existindo, mas todo pedido dele é `DENY_CONTAINED` e as conexões dele caem. Reversível, idempotente; o alcance é o papel de quem o lançou (`process`) |
| `process.release` | Solta o processo isolado — pela mesma permissão (`process`) |
| `agent.suspend` | Suspende um agente: registrado e conectado, mas todo pedido dele e dos processos dele é `DENY_CONTAINED`; as conexões caem e os arrendamentos são soltos. Não é revogação (`key`) |
| `agent.resume` | Retoma o agente suspenso (`key`) |
| `credential.suspend` | Suspende uma credencial — de pessoa ou de agente: login e aperto recusados com `DENY_CREDENTIAL`, as sessões não agem. Não é revogação (`person` ou `key`) |
| `credential.resume` | Retoma a credencial suspensa (`person` ou `key`) |
| `containment.list` | As contenções que valem agora, para quem investiga e recupera — voláteis: nenhuma sobrevive a um boot |
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
├── contencao.rs     as contenções reversíveis — o processo isolado, o agente e a credencial suspensos —, que o gate consulta
├── chaves.rs        as chaves de assinatura das identidades: a privada só no kernel, o nome no espaço do dono, a lápide no journal, e a assinatura gravada antes de sair
├── mensagens.rs     as mensagens entre titulares: um recurso, pelo mesmo ponto de decisão
├── armazem.rs       o armazém montado em /armazem: o lote, do gate ao commit — reconfirmação, arrendamento, cota, rascunhos, cada um no seu lugar
├── volume.rs        o volume do armazém na partição própria: blocos cifrados, o journal dos metadados, o ponto de commit no de estado
├── nativo.rs        a interface nativa: o registro como API dos programas, pelo mesmo gate
├── atividade.rs     quem está agindo: os agentes conectados e quem agiu por último
├── autorizacao.rs   o ponto único de decisão: papel, permissão, recurso, taxa e auditoria
├── metricas.rs      o custo da segurança, medido: contadores atômicos que só a consulta lê, nunca a decisão
├── oleoduto.rs      o caminho da auditoria até o journal: a capacidade que o plano de dados respeita, a partilha entre principais e quem espera por lugar
├── seguranca.rs     o tecido de segurança: o fio do NSF, que lê e pede pelo gate como qualquer principal
├── hora/
│   ├── mod.rs       os três relógios — o monotônico intocado, o civil, o lógico pelo civil —, os tratadores de time.request, time.sync e time.confirm, e o system.info time
│   ├── contador.rs  a régua do civil: o contador do hardware em milissegundos — a frequência declarada no ARM, o TSC calibrado pelo PIT no x86
│   ├── civil.rs     o relógio civil, um só, atrás de uma trava folha: o RTC até o primeiro acordo, e depois só o desfecho de uma rodada ou o salto confirmado
│   ├── rodada.rs    os pedidos em aberto e as rodadas de cada principal: a ordem das fontes, o nonce encadeado, o quórum no fechamento
│   └── servico.rs   o fio do serviço de hora: as rodadas pelas fontes do registro, cada passo pelo gate, como ele mesmo
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
├── rede/
│   ├── mod.rs       o ARP do diagnóstico, e o observador que o deixa conviver com a pilha
│   ├── pilha.rs     a pilha IP — o smoltcp sobre a placa —, o DHCP, a tabela de conexões e o fio que a faz andar
│   ├── conexoes.rs  a conexão como capacidade do registro: de quem ela é, e como o gate a decide
│   ├── canal.rs     o canal do agente por TCP, só o transporte: as vagas, a geração, o prazo do aperto e a contrapressão
│   ├── captura.rs   os datagramas trocados com um destino observado, para quem tem `net.observe` sobre ele
│   ├── bancada_dns.rs  só na suíte: o servidor de DNS da bancada, determinístico, de dentro da máquina
│   ├── bancada_hora.rs só na suíte: as três fontes de Roughtime da bancada, de dentro da máquina, honestas ou torcidas por caso
│   └── espera.rs    a leitura e o envio que esperam: armados na conexão, um de cada sentido, acordados pela pilha ou pelo prazo, decididos de novo na entrega
├── traps.rs         contabilidade de exceções e modo post-mortem
├── nucleos.rs       os vários núcleos: quem ligou, o pulso de cada um, o aviso e o travamento de propósito
├── trava.rs         a trava justa, por senha, que todo o kernel usa
├── ordem_das_travas.rs  só na suíte: a ordem das travas, conferida a cada `lock` — nenhum par em duas ordens
├── irq.rs           contadores de interrupções de hardware
├── tempo.rs         contagem de tempo desde o boot
├── relogio.rs       o RTC (CMOS no x86, PL031 no ARM), que só o relógio civil lê
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
│   ├── codigo.rs    o código que vira processo, lido e conferido uma vez: o da imagem, ou o selado por um editor em que o papel confia
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
├── dns.rs           a pergunta e a resposta do DNS, sem alocar: do programa que resolve, do NSF e da bancada
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
├── codigo.rs        o selo de um editor sobre um executável: Ed25519 estrita sobre o resumo, no fim do arquivo
├── chaves.rs        as chaves de assinatura das identidades e o registro de domínios: o prefixo do domínio seguido de um resumo de 32 bytes, e nada mais
├── gerador.rs       ChaCha20 com apagamento rápido da chave
├── credencial.rs    o verificador Argon2id de uma senha, conferido em tempo constante
├── pessoas.rs       o identificador de uma pessoa e o formato do registro delas
├── quadro.rs        como as mensagens se delimitam no fluxo da porta
└── registro.rs      o formato dos arquivos de chaves autorizadas

politica/src/        a política de autorização, a mesma no kernel e no hospedeiro
├── lib.rs           a cadeia de decisão, e a política padrão da imagem
├── permissao.rs     o vocabulário fechado de permissões, e quais são sensíveis
├── codigo.rs        os códigos de decisão: ALLOW, DENY_*, RATE_LIMIT, INVALID_ARGUMENT, ERROR
├── explicacao.rs    a recusa explicada: a razão, se adianta repetir, o que fazer, e a frase para uma pessoa
├── procedencia.rs   por que um código de fora da imagem não roda: o motivo da auditoria e o código da resposta
├── arquivo.rs       o formato, a validação, a decisão, as regras de mudança e o texto que volta igual
├── caminho.rs       a forma normal dos caminhos, a mesma do VFS
├── endereco.rs      a forma normal dos destinos de rede, `tcp:<ipv4>:<porta>`, a mesma que o kernel disca
├── taxa.rs          o balde de pedidos e a janela de apertos de mão
├── arrendamento.rs  a versão e o arrendamento de cada recurso compartilhado
├── mensagens.rs     as caixas, os estados, as cotas e os nonces das mensagens
├── manifesto.rs     o manifesto de um programa: o nome, o que ele exerce, e o resumo da imagem
├── sigiloso.rs      o texto que sai da memória zerado: o corpo e a resposta que o leva
└── auditoria.rs     os registros e a cadeia de elos BLAKE2s

seguranca/src/       o tecido de segurança (NSF) como conta pura: o que ele vê, liga, detecta e pede — nunca o que alguém pode
├── lib.rs           o que mora aqui, e o que nada aqui faz: decidir
├── evento.rs        o registro da auditoria lido e refeito elo a elo, e o evento de segurança que ele vira
├── grafo.rs         a cadeia causal: quem lançou quem, quem pediu o quê, que nome levou a que endereço
├── ueba.rs          o perfil de comportamento de cada identidade, em conta inteira
├── risco.rs         o risco explicável: cada fator com o motivo
├── regras.rs        as detecções, com nome, severidade e os registros que as dispararam
├── invariantes.rs   a segunda camada: a cadeia que se refaz, a lacuna, o tempo que não volta
├── incidente.rs     o incidente: atores, eventos, evidência, risco, detecções, estado e ações
├── evidencia.rs     o cofre de evidências, com cadeia de resumos própria amarrada à da auditoria
├── resposta.rs      o que o NSF pede e o que recomenda; uma recusa encerra o objetivo
├── dns.rs           o que o NSF vê do DNS pela captura: o nome, o endereço, a pergunta casada
├── firewall.rs      as regras, quem elas alcançam, e o que cada quadro é — só restringe
├── motor.rs         o caminho inteiro: da leitura ao pedido, e o desfecho de volta
├── relatorio.rs     o JSON das consultas `security.*`
├── tempo.rs         o tempo como a auditoria o conta: o estado do civil e os vereditos das fontes — só observa
└── util.rs          hexadecimal, base64, o texto de uma string JSON e um resumo curto

tls/src/             o cliente TLS 1.3 dos programas: o rustls sem std, com um provedor de cifra próprio — o que um certificado prova não autoriza nada
├── lib.rs           o que o pacote pede a quem o usa — a semente, o relógio, as âncoras e o transporte — e o perfil
├── sessao.rs        a conexão: o aperto pela máquina de estados do rustls, os registros, o alerta que sai na recusa e a sessão que quebra
├── falha.rs         a taxonomia: a recusa do transporte passa com o código dela; as do TLS têm os seus
├── provedor.rs      as suítes, os grupos e as assinaturas que o cliente aceita — e nada mais
├── cifra.rs         AES-GCM e ChaCha20-Poly1305 sobre um registro
├── troca.rs         X25519 e P-256, que recusam o ponto que não contribui
├── assinatura.rs    ECDSA P-256 e P-384, Ed25519 estrito e RSA — o PKCS#1 v1.5 na cadeia, o PSS no CertificateVerify —, com o perfil da chave
├── resumo.rs        SHA-256, SHA-384 e o HMAC deles
└── acaso.rs         o gerador da conexão, semeado por quem conecta, que falha fechado sem semente

http/src/            o cliente HTTP/1.1 e HTTP/2 dos programas: nada do HTTP é autorização — o gate decide o destino, e o protocolo é do programa
├── lib.rs           o que é, o que não é, e o que fica de fora de propósito: HTTP/3, fila de pedidos, *push*, cookies além do processo, Brotli, seguir redirecionamento
├── url.rs           só `http` e `https`, o host por nome ou IPv4 na forma normal; o que se recusa de propósito
├── pedido.rs        a linha, o `Host`, os cabeçalhos de quem chama conferidos, e os que só o cliente escreve
├── resposta.rs      a resposta pela RFC 9112: o enquadramento sem ambiguidade, os pedaços, os limites, e quando a conexão fica
├── cliente.rs       um pedido de cada vez numa conexão, e a mesma conexão para o seguinte quando a resposta deixa
├── h2.rs            o HTTP/2: várias correntes numa conexão, lidas num fio só; as janelas de cada uma, e o erro que é da corrente ou da conexão
├── quadro.rs        os quadros do HTTP/2 lidos e escritos, cada recusa da RFC 9113 com o código e o alcance dela
├── hpack.rs         o HPACK: a tabela dinâmica do servidor mantida a cada bloco, e o que este lado manda sem indexar nada
├── huffman.rs       o código de Huffman do HPACK, canônico, sem árvore; o EOS e o preenchimento torto recusados
├── codificacao.rs   o corpo comprimido: `gzip` e `deflate` negociados pelo pedido, conferidos, e decodificados com o teto de quem pede
├── cookies.rs       o pote do programa: o `Set-Cookie` lido, o domínio, o caminho, o `Secure`, o `HttpOnly`, o `SameSite`, a validade e os tetos — estado do processo, e não credencial
├── inflar.rs        o DEFLATE, escrito aqui: o que a RFC 1951 proíbe é recusado, e a saída para no teto
├── erro.rs          a falha de baixo como veio, a conversa que acabou cedo, o protocolo, os limites e o conteúdo que não se decodifica
├── categoria.rs     de que família é o código de uma falha — o gate, a contenção, o firewall, o DNS, o transporte, o prazo, o TLS
├── testes.rs        cada resposta partida em todo tamanho de pedaço, contra um transporte de mentira
├── testes_da_codificacao.rs  o DEFLATE contra o zlib e contra símbolos escritos à mão; cortes, bits trocados, bombas e o monte medido
├── testes_dos_cookies.rs    as regras do pote, uma a uma; potes que não se veem, o relógio lido só quando precisa, e o lixo do servidor que não o quebra
├── testes_do_hpack.rs  os exemplos da RFC 7541 byte a byte, cada byte pelo Huffman, e os blocos hostis; `tests/nghttpd.rs`, o cliente contra o servidor da nghttp2
├── testes_dos_quadros.rs  cada quadro lido e escrito, e cada recusa com o alcance certo
└── testes_do_h2.rs  a conexão contra um servidor de mentira que respeita as janelas, e contra roteiros hostis: o erro e o alcance de cada um

web3/src/            os protocolos Web3 de um programa: o Internet Computer, a consulta e a chamada verificadas — o que se prova não autoriza nada
├── lib.rs           o que o pacote é, e o que nada nele faz: rede, relógio, aleatório ou decisão
├── icp.rs           o Internet Computer de quem consulta: os módulos, e de onde vem cada regra — a especificação, a referência oficial
└── icp/
    ├── principal.rs  o Principal: os bytes, o texto com o CRC32, e a forma canônica que se recusa a variar
    ├── principal/
    │   └── testes.rs  contra a especificação e contra o `ic_principal`
    ├── cbor.rs       o subconjunto estrito do CBOR que o IC usa, lido e escrito
    ├── cbor/
    │   └── testes.rs  os casos de borda, e o `serde_cbor` como oráculo
    ├── resumo.rs     o hash independente de representação: o id de um pedido e o que um nó assina
    ├── resumo/
    │   └── testes.rs  os exemplos da especificação, e o `ic-transport-types` como oráculo
    ├── pedido.rs     os envelopes da consulta, da chamada e da leitura de estado — do anônimo, ou com a pública e a assinatura de quem chama —, e o id do pedido
    ├── pedido/
    │   └── testes.rs  o mesmo id, e o envelope que o `ic-transport-types` lê
    ├── arvore.rs     a árvore de hash de um certificado: a leitura, a raiz e a procura
    ├── arvore/
    │   └── testes.rs  contra o exemplo da especificação e contra o `ic-certification`
    ├── certificado.rs  o certificado: a assinatura BLS, a delegação de um nível, as faixas da sub-rede e o tempo
    ├── certificado/
    │   ├── testes.rs  contra a bancada e contra o `ic-certificate-verification`
    │   └── rede_principal.rs  respostas gravadas da rede principal, conferidas pela raiz dela — `web3/dados/rede_principal/`
    ├── assinatura.rs  a assinatura Ed25519 de um nó, pela ZIP215
    ├── assinatura/
    │   └── testes.rs  a ZIP215 daqui contra o `ic-ed25519`
    ├── consulta.rs   a resposta da consulta e as assinaturas dos nós da sub-rede, presas a este pedido
    ├── consulta/
    │   └── testes.rs  contra a bancada e o `ic-transport-types`
    ├── candid.rs     o Candid: a tabela de tipos inteira, os valores de um subconjunto, e o que sobra recusado; e a escrita com o tipo dado — `opt`, `vec`, `record`, `variant`
    ├── candid/
    │   └── testes.rs  contra a especificação e contra o crate `candid`, nos dois sentidos, com tipos e valores sorteados
    ├── icrc1.rs      o ICRC-1 de um ledger: a conta, a transferência, o saldo, e o bloco ou a recusa pelo nome do padrão — o que não tem a forma dele não vira bloco
    ├── icrc1/
    │   └── testes.rs  contra o `icrc-ledger-types`, nos dois sentidos
    ├── cmc.rs        o CMC: a conta de depósito de quem cunha, o memo `MINT` e o `notify_mint_cycles`
    ├── cmc/
    │   └── testes.rs  contra a interface do CMC, declarada com o `candid`
    ├── ciclos.rs     o ledger de cycles: a criação de um canister pago com cycles e a carga de cycles num canister, e o canister, o bloco ou a recusa pelo nome da interface
    ├── ciclos/
    │   └── testes.rs  contra a interface do ledger de cycles, declarada com o `candid`
    ├── gerenciamento.rs  o canister de gerenciamento: instalar um módulo, inteiro ou em pedaços, e ler o estado de um canister — o que não tem a forma da interface é recusado
    ├── gerenciamento/
    │   └── testes.rs  contra o `ic-management-canister-types`, nos dois sentidos
    ├── agente.rs     a consulta ponta a ponta — do anônimo, ou assinada por quem tem chave — sobre um transporte de quem chama: nada se entrega antes da verificação
    ├── agente/
    │   └── testes.rs  contra um IC de mentira, os modos adversários de quem está no caminho, e a medida da consulta no hospedeiro
    ├── atualizacao.rs  a chamada de atualização: as faixas, a chamada pela `/api/v4` e a situação enquanto pendente, cada leitura outro pedido, assinado de novo — e a do canister de gerenciamento, pelo canister efetivo; nada se entrega antes da verificação
    ├── atualizacao/
    │   └── testes.rs  contra um IC de mentira: o envelope e o id pelo `ic-transport-types`, a assinatura pelo `ic-ed25519`, e as recusas
    ├── situacao.rs   o `request_status` de um certificado: recebida, processando, respondida, recusada, acabada
    ├── situacao/
    │   └── testes.rs  contra árvores do `ic-certification`
    ├── registro.rs   `/dados/icp/redes`: as redes em que se confia, a chave da raiz de cada uma — um erro recusa o arquivo inteiro
    ├── registro/
    │   └── testes.rs  o arquivo de redes, linha a linha
    └── bancada.rs    só nos testes: chaves, certificados e respostas de um IC de mentira, montados com as bibliotecas oficiais

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

hora/src/            a hora como conta pura: o Roughtime da RFC 10049, versão 1, conferido, e o relógio civil disciplinado — uma resposta não escolhe a hora
├── lib.rs           o que mora aqui, de onde vem o que se sabe do protocolo — reproduzido, da referência, pendente — e o que não se declara
├── moldura.rs       o `ROUGHTIM`, o comprimento exato e o teto do pacote
├── mensagem.rs      o cabeçalho, as etiquetas em ordem little-endian e os valores como fatias do que chegou — nada se reescreve
├── merkle.rs        a folha, que é o pacote inteiro do pedido; o nó; e a subida pelo caminho e pelo índice
├── pedido.rs        o pedido da versão 1, de 1024 bytes, com o `SRV` da chave fixada, e a folha dele
├── resposta.rs      a conferência: a forma, as duas assinaturas sobre os bytes recebidos, e só então o que a resposta afirma
├── resposta/
│   └── testes.rs    os dois vetores externos, e uma resposta torta para cada conferência — torta só naquilo
├── pedidos.rs       os pedidos em aberto: o id ligado ao principal, à fonte, à chave e à folha; a recusa não consome, a primeira válida sim
├── encadeamento.rs  o nonce do próximo pedido da rodada, tirado da resposta anterior
├── intervalo.rs     a amostra: o intervalo da hora no instante da chegada, levado adiante com a deriva
├── quorum.rs        o acordo de pelo menos duas chaves: cada chave conta uma vez, e o empate é recusado
├── disciplina.rs    o relógio civil: o ajuste gradual, o salto em duas rodadas, o teto, o salto pendente e os estados
├── disciplina/
│   └── testes.rs    o relógio atrasado, o adiantado, o salto, a perda e a volta das fontes, e a monotonicidade por sorteio
├── registro.rs      `/etc/duke/tempo`: as fontes em que se confia, o quórum de pelo menos duas chaves e os tetos — um erro recusa o registro inteiro —, e a coerência com a política
├── registro/
│   └── testes.rs    k = 0, k = 1, k acima das fontes, a chave que não serve, o destino que não é UDP, a fonte sem destino na política
└── servidor_de_teste.rs  só nos testes: um servidor que responde como a versão 1 — ou, de propósito, de outro jeito

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
    ├── dns.rs       resolver um nome como programa: a associação com o servidor, que o gate decide, a pergunta e a resposta
    ├── conexao.rs   a conexão TCP de um programa, pelo gate: a recusa, o firewall, o outro lado e o prazo, sem se misturarem
    ├── tls.rs       o TLS de um programa: a semente, o relógio e as âncoras, cada um pelo gate, sobre a conexão
    ├── http.rs      o HTTP de um programa: o nome pelo DNS dele, o destino pelo gate, o TLS no meio, e a falha de quem falhou
    ├── icp.rs       o Internet Computer de um programa: a consulta e a chamada verificadas do `web3` sobre o HTTPS dele, assinadas pela chave que o kernel guarda, e a declaração do desfecho pelo `audit.declare`
    ├── superficie.rs uma camada do compositor com os pixels no processo
    ├── janela.rs    a moldura, o arrasto e a caixa de fechar, e a interface dentro dela
    └── bin/
        ├── ola.rs        o primeiro programa em Rust: monte, formatação e pilha
        ├── memoria.rs    confere `mapear` e o monte do lado de quem pede
        ├── ponteiros.rs  pede ao kernel que escreva no código, e confere a recusa
        ├── autoridade.rs confere de dentro que o processo age com o papel de quem o lançou
        ├── eco.rs        escuta um canal de eventos e diz o que chega
        ├── cedente.rs    cede a vez duas mil vezes, em várias cópias, e confere que voltou inteiro
        ├── colhedor.rs   bifurca, e só colhe o filho quando a suíte manda: no meio, o filho é um zumbi
        ├── janelas.rs    o servidor de janelas: moldura, foco, arrasto, ordem e fechar
        ├── superficie.rs desenha numa superfície, bifurca, fecha e sai sem fechar
        ├── herdeira.rs   depois de um `exec`, fecha a superfície herdada sem perder a sua
        ├── cobrir.rs     um programa hostil: pinta uma barra falsa e tenta pô-la sobre a do kernel
        ├── pseudo.rs     digita no interpretador pelo pseudo-terminal, e lê a resposta
        ├── entrada.rs    uma janela fora do servidor, com o canal de entrada dela
        ├── formulario.rs dois campos e dois botões do toolkit, que o agente preenche
        ├── nativo.rs     um programa nativo: confere de dentro o que a interface nativa promete
        ├── contido.rs    declara só `system.read`, e confere que o manifesto limita o resto
        ├── isolavel.rs   pede pelo gate a cada passo da suíte: isolado, ouve `DENY_CONTAINED` e não bifurca; solto, pede de novo
        ├── anonimo.rs    o único sem manifesto: não exerce nada, nem lançado pelo sistema
        ├── guardar.rs    guarda no armazém pelo `pedir`: a versão, o conflito, a leitura pelo descritor e o `MUDOU`
        ├── discador.rs   conversa com o eco da bancada pelo `pedir`: os 256 bytes de ida e volta, e as recusas
        ├── resolvedor.rs resolve nomes pelo DNS da bancada, e confere que a resposta não dá acesso: o gate decide o endereço
        ├── cifrado.rs    conversa TLS com o eco da bancada: o nome provado, o segredo cifrado, as cadeias P-384, RSA e mista, e as recusas — do gate antes, do programa depois
        ├── pausado.rs    uma sessão TLS, pela cadeia mista, que a suíte interrompe no meio: a política, o firewall e a contenção chegam com o código deles
        ├── pagina.rs     busca páginas na bancada, claro e cifrado: cada página, cada falha com o código e a família dela, e as medidas
        ├── buscador.rs   uma conversa HTTP que a suíte interrompe no meio: a revogação, a contenção, o firewall e o fim chegam com o código deles
        ├── consulta.rs   uma visita curta à bancada, para várias correrem ao mesmo tempo com a autoridade de cada um
        ├── instalador.rs baixa código da bancada pelo DNS, TCP, TLS e HTTP, grava no armazém e o executa num filho: o kernel confere o selo
        ├── vazao.rs      traz 5 MiB da bancada, claro e cifrado, pelo plano de dados: cada leitura decidida e gravada, sem a ficha do papel
        ├── compressao.rs o HTTP comprimido da bancada, claro e cifrado: decodificado no processo, negociado, o estragado e a bomba com o código deles
        ├── cookies.rs    a sessão da bancada no pote do processo, clara e cifrada: o isolamento, os atributos, a validade, os tetos, e a recusa que é do gate
        ├── correntes.rs  o HTTP/2 da bancada, h2c e pelo ALPN: correntes ao mesmo tempo numa conexão, o erro da corrente e o da conexão, e a recusa que é do gate
        ├── validade.rs   diz com que hora o sistema confere validades, e o que ela deu: um certificado válido, um vencido e um ainda não válido, e os cookies com `Expires` e `Max-Age`
        ├── carga.rs      quatro conexões com o eco ao mesmo tempo, 256 KiB de ida e volta em cada, cada uma com os bytes dela
        ├── insistente.rs passa dados pela conexão aberta, e insiste, no passo que a suíte dita: a revogação, a contenção e o firewall no meio
        ├── vindo.rs      o programa que chega pela rede: fora da imagem, selado pela bancada, e pede pelo gate
        ├── legado.rs     pede, não busca a resposta e troca de imagem: a nova não a encontra
        ├── icp.rs        consulta o canister da bancada pelo DNS, TCP, TLS e HTTP, confere a prova de dentro e declara o desfecho: a prova não dá acesso a nada
        ├── verificado.rs o IC na imagem de produção: o texto e o eco verificados pela rede sem DNS, a prova adulterada recusada, cada consulta medida e declarada
        ├── livro.rs      a rede principal do IC, de verdade: o símbolo do livro-razão do ICP pelo DNS, o gate, o TLS público e a verificação pela raiz da imagem, cada parte medida
        ├── carteira.rs   o valor na bancada do IC, pela chave de quem a lançou: o saldo, a transferência do ICRC-1, a repetição que o ledger deduplica e ICP em cycles pelo CMC — cada resposta verificada, cada assinatura uma decisão do gate
        ├── implantacao.rs um canister na bancada do IC, pela chave de quem a lançou: a criação pelo ledger de cycles, a instalação de um módulo do armazém, o estado, o upgrade em pedaços que guarda o estado e a carga de cycles — cada resposta verificada, cada assinatura uma decisão do gate
        └── terminal.rs   o Terminal: o interpretador numa janela, pelo pseudo-terminal

xtask/src/
├── main.rs          a ferramenta de build, teste e diagnóstico do projeto
├── canal_tcp.rs     o canal do agente por TCP do lado de fora: a porta encaminhada, e a ponte da suíte — `xtask/bancada/ponte.py`
├── codigo.rs        o código publicado: fora da imagem, selado pelos editores da bancada, servido pelo HTTP dela em `/codigo`
├── icp.rs           a bancada do IC: a PocketIC fixada e conferida pelo SHA-256, o canister da bancada, e o proxy TLS que mente de um jeito por nome — `xtask/bancada/icp.py` —, a cada conexão; e os módulos que o `implantacao` instala
├── persistencia.rs  a bancada de persistência: a mesma máquina em vários boots, com corte de energia
├── rede_principal.rs a fumaça real da rede principal do IC, à mão e fora da CI: o pré-voo do TLS, os destinos pelo `policy.write`, a consulta, a auditoria e a revogação
├── servidor_de_hora.rs as fontes de Roughtime da bancada de tempo, no hospedeiro: escritas à parte do pacote `hora`, com um modo por fonte
├── tempo.rs         a bancada de tempo: o Roughtime pela rede de verdade, do gate ao servidor e de volta, uma máquina por cenário
└── tls.rs           a bancada TLS: a PKI gerada a cada máquina — as raízes P-256, RSA e P-384 e as cadeias com a forma das públicas —, o eco TLS — o OpenSSL, por `xtask/bancada/tls.py` —, e o servidor HTTP claro e cifrado, HTTP/1.1 e HTTP/2 — `xtask/bancada/http.py` e `http2.py` —, a cada conexão
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
passando pelos núcleos. Ele exige que passem por pelo menos dois, e dá
tempo para isso: no kernel de release o trabalho inteiro cabia em menos
de um tique, e o CI do ARM viu duas vezes os oito fios acabarem no núcleo
que os pegou primeiro. Agora eles seguem trabalhando enquanto um núcleo
só os viu, até um prazo. Repetido quarenta vezes num boot do ARM release,
o caso antigo falhou em cinco rodadas, e o novo em nenhuma.

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
ainda é parado. A NMI é a mesma para os dois, e quem a recebe decide pela
parada em curso; quem conduz a parada não para por ela — um aviso de
descarte mandado antes da parada e entregue depois chega a ele também. No
ARM a invalidação da TLB é difundida pelo próprio hardware (`tlbi …is`), e
a parada vai por uma SGI só dela, que **não** atravessa a máscara: um
núcleo mascarado fica de fora, e o relatório o lista em
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
que a pessoa confira é da fase 13.

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
buffer do programa. Buscada, ela vem inteira, do tamanho que tiver: o teto
de 4 KiB por chamada é para o tamanho que o processo escolhe, e não para a
resposta, que o kernel montou — com ele, um `fs.read` ou um `net.recv` de
4096 bytes em base64 nunca chegava ao programa. E o anexo de um pedido vai
até `MAIOR_ANEXO`, 60 KiB, como a interface promete.

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

Dezenove mutações contra o que a auditoria do estado depois das
limitações corrigiu — a cessão de dentro do handler, o estouro na guarda,
a compactação sem fila, as travas nos dois modos, o `fs.read`, o
silêncio do canal e o fio ocioso que segurava o núcleo —, cada uma contra
a suíte de quatro núcleos ou a fumaça da arquitetura dela: **dezenove
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
| a coleta atrasada conta como silêncio (o relógio da drenagem no lugar da linha vista vazia) | o mesmo caso |
| a coleta nunca anota a linha vista vazia | a fumaça do x86: `fragmento: o pedido colou no pedaço abandonado` |
| o coletor dorme com outros prontos (x86) | `fios: quem nao tem o que fazer da a vez` — cem cessões em 500 tiques |
| `ha_outro_pronto` sempre falso (ARM) | o mesmo caso, os mesmos 500 tiques |

Duas mudaram a suíte antes de reprovar como deviam. Só o núcleo dos
dispositivos andando o relógio era pega pelo limite de andamento, dez
minutos depois, e não pelo caso: o fio que mede esperava o relógio parado;
agora o prazo dele é o timer do próprio núcleo. E a da suíte que esvazia as
mensagens sem o journal, numa primeira rodada com a bancada carregada,
reprovou por um caso de coordenação; refeita sem carga, só o da
reconstrução.

## Rede nativa

Um programa do Duke não abre um socket do Unix: pede uma conexão ao
registro — `net.connect`, com o destino inteiro, `tcp:<ipv4>:<porta>` ou
`udp:<ipv4>:<porta>` —, pelo mesmo gate de todo comando, e o destino é o
**recurso** que a política decide. O protocolo é do [`smoltcp`](https://github.com/smoltcp-rs/smoltcp)
(Ethernet, ARP, IPv4, DHCP, TCP, UDP): escrever TCP do zero é um a dois
anos-pessoa e não diferencia o sistema em nada. O que diferencia é o lado
de cima, e esse é do kernel.

```
$ cargo xtask agent net.connect '{"to":"tcp:10.0.2.100:7"}'
{"connection":1,"to":"tcp:10.0.2.100:7","state":"connecting"}
$ cargo xtask agent net.send '{"connection":1,"content":"ola, rede do Duke\n"}'
{"connection":1,"sent":18,"state":"established"}
$ cargo xtask agent net.recv '{"connection":1}'
{"connection":1,"state":"established","returned":18,"encoding":"utf-8","content":"ola, rede do Duke\n"}
$ cargo xtask agent net.connect '{"to":"tcp:10.0.2.100:8"}'
{"error":{"code":-32010,"message":"operacao negada pela politica","data":"DENY_RESOURCE"}}
```

**O alcance é enumerado.** A permissão `net.connect` é sensível — não vem
por inclusão de outro papel — e cada papel que a tem escreve, numa linha
`recurso`, os destinos que alcança, cada um inteiro e na forma normal
(`politica::endereco`): `recurso operador net.connect tcp:10.0.2.100:7
udp:10.0.2.2:69`. Sem curinga, sem faixa, sem "qualquer porta" — nem para
o sistema. O protocolo é parte do destino: `tcp:10.0.2.2:69` e
`udp:10.0.2.2:69` são dois destinos, e a linha que alcança um não alcança
o outro. A forma normal recusa o ambíguo em vez de adivinhar:
`tcp:010.0.2.100:7` não é lido como outra coisa, é uma linha que não vale.
O teto do `policy.write` vale como para os caminhos: ninguém concede um
destino que o administrador não alcança. A imagem de desenvolvimento
enumera os destinos da bancada, todos servidos pelo próprio emulador, sem
servidor nem porta aberta no hospedeiro: o eco TCP em `10.0.2.100:7` — um
`guestfwd` que roda `cat` a cada conexão —, o eco TLS em `10.0.2.100:443`
— outro `guestfwd`, que roda o servidor TLS da bancada a cada conexão (ver
[O TLS de um programa](#o-tls-de-um-programa)) —, o TFTP do emulador em
`10.0.2.2:69`, que serve um arquivo que o `xtask` escreve, e o DNS do
emulador em `10.0.2.3:53`.

**Usar a conexão também é decidido.** `net.send`, `net.recv` e
`net.close` nomeiam a conexão pelo número, e o gate resolve o número no
destino dela, **para quem pede**, antes de decidir — a mesma conta de
`message.send`, que resolve o destinatário. Uma revogação, uma troca de
papel ou uma política nova valem no pedido seguinte, para a conexão já
aberta. Cada pedido vai para a auditoria com o destino; a recusa, com o
motivo.

**A conexão é de quem a abriu**, pelo caminho por onde o pedido veio: uma
sessão do canal (a porta, a chave e a geração da porta — o agente que
desconecta perde as dele, e o seguinte na mesma porta não as herda), uma
pessoa (a sessão dela), um processo (o fio dele — e não a autoridade de
quem o lançou: o agente não lê a conexão do programa que lançou, nem o
programa a do agente). O número de outro titular e um que não existe têm a
mesma resposta, `DENY_RESOURCE`: quem pergunta não descobre o que é dos
outros. Quando o dono acaba — o processo morre, a porta reabre, a pessoa
sai —, o coletor de fios derruba a conexão na passada seguinte e a grava
na auditoria, como faz com as camadas de um processo morto.

**Tetos.** Dezesseis conexões na máquina, quatro por titular — conexões
TCP e associações UDP juntas —, 16 KiB em cada sentido de uma conexão TCP
— o buffer, que é também a janela: ver [A janela do TCP](#a-janela-do-tcp)
— e 4 KiB numa associação UDP.
São tetos de recurso, e não autorização: a decisão é a da política, e o
teto só impede um titular de tomar a tabela dos outros. Por isso a
conexão que o dono fechou e que ainda espera o outro lado terminar o fecho
conta no teto **dele**: sem isso, um titular cujo outro lado não fecha
enchia a tabela da máquina com fechos que não eram de ninguém — a suíte o
mostrou, com um `sleep` da bancada em `10.0.2.100:9` que não fecha por
trinta segundos. E o fecho
termina quando o outro lado também fechou — no `TIME_WAIT`, ou no
`CLOSING`, quando os dois FIN se cruzam —, e não dez segundos depois, como
o `smoltcp` o guardaria: cada conexão nova pega a porta local seguinte numa
faixa de milhares, e guardar os fechos já terminados fazia titulares novos
ouvirem "tabela cheia" sem conexão viva de ninguém. A conexão derrubada —
pelo firewall, ou porque o dono acabou — termina quando o RST dela sai, e
não antes: se o vizinho pede um ARP, o RST espera a resposta, até dois
segundos.

**A associação UDP.** Um destino `udp:` abre uma associação: a mesma
capacidade, com o mesmo número, o mesmo dono, a mesma decisão a cada uso,
o mesmo teto e a mesma espera — e outra unidade, o datagrama:

```
$ cargo xtask agent net.connect '{"to":"udp:10.0.2.2:69"}'
{"connection":2,"to":"udp:10.0.2.2:69","state":"open"}
$ cargo xtask agent net.send '{"connection":2,"content":"\u0000\u0001bancada.txt\u0000octet\u0000"}'
{"connection":2,"sent":20,"state":"open"}
$ cargo xtask agent net.recv '{"connection":2,"wait":5000}'
{"connection":2,"state":"open","returned":516,"datagram":516,"encoding":"utf-8","content":"\u0000\u0003\u0000\u0001bancada udp 000\n…"}
```

- `net.send` manda **um** datagrama, inteiro ou nada, de até 1472 bytes —
  o quadro menos os cabeçalhos, porque a pilha não fragmenta. Um byte a
  mais é recusado com o motivo, em vez de cortado ou perdido. A fila de
  saída guarda oito datagramas; cheia — o vizinho ainda sem resposta ao
  ARP —, o seguinte também é recusado com o motivo, e não aceito e perdido
  calado.
- `net.recv` devolve **um** datagrama inteiro, com o tamanho em
  `datagram`, ou nenhum. O que não cabe no `max` de quem lê fica onde está,
  e a resposta diz o tamanho: um datagrama não se corta, e o resto dele
  não viria depois. Dois que chegaram juntos saem um de cada vez.
- O socket UDP recebe de qualquer origem na porta dele. O que não veio do
  destino da associação — outra porta, outro endereço — sai na volta da
  pilha em que chega à frente da fila, e é contado em `net.info`
  (`foreign_datagrams_dropped`): a associação é uma conversa com o destino
  que o gate decidiu, e nada de outro chega a quem a abriu, nem fica
  ocupando a fila dela à espera de uma leitura. Um datagrama alheio acorda
  o waker de quem espera — o socket não sabe de origem —, e quem espera
  não acha nada e volta a esperar.
- Duas associações vivas não dividem a porta local: o socket UDP recebe
  pela porta, e a segunda nunca ouviria nada. A faixa dá a volta e pula a
  porta de uma associação viva.
- Não há aperto nem fecho com o outro lado: o estado é `open` do começo ao
  fim, e fechar solta a porta e devolve a vaga do teto na hora.

A bancada é o TFTP do próprio emulador, que responde sempre da mesma
porta: um pedido de leitura sai, e o arquivo volta em dois datagramas, de
516 e 132 bytes. O maior datagrama também tem resposta: um pedido de
leitura completado até 1472 bytes com uma opção que o TFTP não conhece, e
ignora — cortado, perderia o zero do fim, e o TFTP o recusaria. O
datagrama de outra origem a suíte injeta na pilha, num quadro montado por
ela: a bancada não tem quem mande. E a fila cheia ela faz com um destino
do enlace que não responde ao ARP — o emulador só responde pelos endereços
dele —, posto na política só durante o caso.

**Quem faz a pilha andar** é um fio do kernel, `rede`, que sonda a pilha
e descansa até a próxima interrupção — dando a vez a quem estiver pronto.
Quem pede sonda na hora, dentro do comando: o SYN de um `net.connect` sai
no próprio pedido. A pilha é a **única** que colhe quadros da placa: o
ARP do diagnóstico (`net.arp`) continua, e lê a resposta dele num
observador por onde a pilha passa cada quadro antes de processá-lo — dois
consumidores da mesma fila perderiam cada um os quadros do outro.

O programa [`discador`](programas/src/bin/discador.rs) faz o caminho
inteiro de dentro de um processo, pelo `pedir`, com o manifesto
declarando `net.connect`: os 256 valores de um byte vão pelo anexo do
pedido e voltam, em texto quando são texto e em `base64` quando não são; a
porta ao lado do eco é `DENY_RESOURCE`; lançado por uma pessoa
observadora, `DENY_PERMISSION`. E pelo UDP pede o arquivo da bancada ao
TFTP do emulador, e o recebe em dois datagramas inteiros, confirmando cada
bloco. E ele não pergunta de novo a cada volta: cada leitura espera — ver
a seguir.

**A leitura que espera.** `net.recv` com `wait` — em milissegundos, até
dez segundos — não responde vazio quando nada chegou: o pedido dorme até
a pilha ter o que dizer — chegou dado; o estado mudou, porque o aperto
terminou, o outro lado fechou ou a conexão caiu; a conexão acabou — ou
até o prazo vencer. Quem acorda é a pilha: o socket do `smoltcp` guarda o
waker de quem espera e o aciona na volta em que processa o evento, no fio
`rede` ou no comando que a sondou. Quem espera não pergunta nada enquanto
isso, e o prazo é o do relógio das tarefas, acordado pelo tique.

```
$ cargo xtask agent net.recv '{"connection":1,"max":0,"wait":5000}'
{"connection":1,"state":"established","returned":0,"encoding":"utf-8","content":""}
```

O handler não espera: rodaria no executor, e prenderia atrás dele todos
os canais, os consoles e os processos. Ele **suspende** — arma a espera
na conexão e volta sem resposta —, e quem despachou o pedido espera por
ele sem prender os outros: a tarefa da sessão do canal, que só atende
aquele agente, e em que o que veio atrás do pedido, no mesmo quadro,
espera a vez na ordem; a tarefa `programas`, que guarda os pedidos
suspensos dos processos e segue atendendo os outros, com o fio do
processo dormindo como em qualquer pedido; e o interpretador, que guarda
o suspenso de cada console — a entrada daquele console fica na fila — e
segue atendendo os outros consoles e as janelas.

**A entrega é decidida de novo.** Acordado, o pedido é executado outra
vez, inteiro, pelo mesmo gate: uma decisão nova, com a política, o
registro e a sessão de agora, gravada na auditoria. A decisão de antes da
espera não vale para depois dela, como a de um pedido não vale para o
seguinte: a política que tira o destino do alcance no meio da espera
recusa a entrega, e o dado fica na conexão. Uma leitura que espera custa
duas decisões — a que suspendeu e a da entrega —, e não uma por volta de
um laço. O cliente que sai durante a espera não recebe nada, e o seguinte
na mesma porta não herda a resposta; o console que fecha ou reabre larga
o comando que esperava.

**A espera é pelo que quem pede ainda não sabe.** A conexão guarda o
último estado que uma resposta disse ao dono — a de `net.connect`,
`net.send` ou `net.recv` —, e a espera só arma se nada mudou desde então.
O aperto que termina entre a resposta do `net.connect`, que disse
`connecting`, e o `net.recv` seguinte já é novidade: a leitura responde
`established` na hora. Armada pelo estado de agora, ela esperava um dado
que o eco só manda quando recebe — a fumaça mediu cinco segundos de
espera, até o prazo, por um aperto que tinha levado milissegundos.

**Uma espera por conexão.** O socket guarda um waker só: a segunda espera
na mesma conexão — o mesmo dono pedindo pelo canal e pelo Terminal em que
confirma uma linha — apagaria a primeira, que passaria a acordar só no
prazo. Ela é recusada — `INVALID_REQUEST`, com o motivo.

**O envio que espera.** `net.send` com `wait` — os mesmos milissegundos,
até dez segundos — não responde "nada coube" quando a fila de saída da
conexão está cheia: o pedido suspende até a pilha abrir espaço — o outro
lado confirmou e a fila andou —, até o estado mudar, ou até o prazo. É a
mesma espera da leitura, no outro sentido: o socket guarda um waker de
cada sentido, e uma conexão aceita um envio e uma leitura esperando juntos
— a segunda espera do **mesmo** sentido é recusada com o motivo. Sem ela,
quem tem mais a mandar do que cabe na fila só podia perguntar de novo em
laço — cada volta uma decisão do gate e um registro na auditoria;
o TLS, que manda vários registros de uma vez, girava.

A entrega é decidida de novo, como a da leitura, e leva os mesmos bytes:
o anexo de um envio que esperou vai junto do pedido suspenso — no texto do
pedido do processo, e numa cópia que o canal do agente guarda, porque a
porta já o entregou. Sem a cópia, a reexecução pelo canal tirava da porta
o que houvesse lá — nada —, e o envio que esperou espaço era recusado por
um anexo que não confere.

### O TLS de um programa

O TLS 1.3 é do **programa**, como o DNS: o pacote [`tls`](tls/src/lib.rs)
é o [`rustls`](https://github.com/rustls/rustls) sem `std`, com um provedor
de cifra próprio sobre as implementações do RustCrypto e do dalek — AES-GCM
e ChaCha20-Poly1305, X25519 e P-256, ECDSA P-256 e P-384, Ed25519 e a
verificação RSA —, e
[`programas::tls`](programas/src/tls.rs) dá a ele o que ele pede a quem o
usa, cada coisa pelo gate:

- a **semente** de cada conexão: 32 bytes do `random.read`, o gerador do
  kernel — a única fonte de acaso de um programa, e uma permissão do papel
  (o operador, o administrador e o sistema a têm; o observador e o tecido
  de segurança, não). Sem ela, nenhum byte do TLS sai;
- a **hora** da validade: a do objeto `time` do `system.info`, por uma
  regra só, a de `protocolo::usuario::hora` — o civil quando a hora é
  autenticada (`sincronizado`, `holdover`), o tempo lógico quando não é
  (`rtc`, `vencido`) —, e nunca o RTC cru: um RTC atrasado de propósito
  não ressuscita um certificado vencido, e o lógico parado à frente da
  hora autenticada não vence um que vale (ver [Os consumidores da
  hora](#os-consumidores-da-hora)). Sem hora, a conexão é recusada, e
  não aceita sem conferir a validade;
- as **âncoras**: um arquivo PEM lido por `fs.read`;
- o **transporte**: a conexão do `net.connect`, com cada `net.send` e cada
  `net.recv` decididos de novo e esperando o evento da pilha, sem girar.

```
cifrado: tcp:10.0.2.100:444 -> DENY_RESOURCE: o gate recusou antes do TLS
cifrado: tcp:10.0.2.100:443 provou ser bancada.duke (TLS13_AES_256_GCM_SHA384, X25519) em 150 ms
cifrado: o segredo e 49086 bytes foram e voltaram cifrados em 260 ms
cifrado: tcp:10.0.2.100:443 provou ser p384.duke (TLS13_AES_256_GCM_SHA384, X25519) em 170 ms
cifrado: tcp:10.0.2.100:443 provou ser rsa.duke (TLS13_AES_256_GCM_SHA384, X25519) em 110 ms
cifrado: tcp:10.0.2.100:443 provou ser misto.duke (TLS13_AES_256_GCM_SHA384, X25519) em 100 ms
cifrado: outro.duke -> TLS_NAME_MISMATCH: o programa recusou
cifrado: estranho.duke -> TLS_UNTRUSTED: o programa recusou
cifrado: vencido.duke -> TLS_EXPIRED: o programa recusou
cifrado: intruso.duke -> TLS_UNTRUSTED: o programa recusou
cifrado: falso-p384.duke -> TLS_UNTRUSTED: o programa recusou
cifrado: falso-rsa.duke -> TLS_UNTRUSTED: o programa recusou
cifrado: tcp:10.0.2.100:7 nao fala TLS: TLS_HANDSHAKE_FAILED
```

**O certificado não autoriza nada.** O destino é decidido pelo gate antes
do primeiro byte do TLS — fora do alcance, a recusa é do gate, e o
`ClientHello` nem é montado —, e o nome que o programa quer provar não é
recurso da política: o mesmo `tcp:10.0.2.100:443`, decidido `ALLOW` pela
política, serve quatro nomes que o programa aceita — de cadeias P-256,
P-384, RSA e mista — e seis que ele recusa. A
sessão cifrada não autoriza o que vem depois do aperto: a política que
tira o destino, o processo isolado e a regra do firewall valem no envio
seguinte, no meio dela.

**As falhas não se misturam.** A recusa do gate e a do firewall passam
pelo TLS com o código de quem recusou — `DENY_RESOURCE`, `DENY_CONTAINED`,
`FIREWALL_BLOCKED` —, sem virar um código do TLS; as do TLS têm os seus
(`TLS_UNTRUSTED`, `TLS_NAME_MISMATCH`, `TLS_EXPIRED`, `TLS_NOT_YET_VALID`,
`TLS_HANDSHAKE_FAILED`, `TLS_TAMPERED`, `TLS_INTERRUPTED`), e as locais
também (`ENTROPY_UNAVAILABLE`, `CLOCK_UNAVAILABLE`). Quando o programa
recusa o certificado, o servidor ouve por quê — o alerta sai antes de a
conexão fechar. Uma sessão que falhou fica quebrada com a falha que a
quebrou: o registro que não saiu já gastou o número dele, e o seguinte
sairia com o número errado.

**O perfil é estreito, de propósito.** Só TLS 1.3; três suítes; dois
grupos; as assinaturas que as cadeias das autoridades públicas usam —
ECDSA P-256 e P-384, cada uma só com o hash dela, Ed25519, e RSA de 2048 a
4096 bits, o PKCS#1 v1.5 na cadeia e o PSS no aperto —, e nenhuma outra:
nem SHA-1, nem P-521, nem a curva com o hash da outra, nem o certificado
assinado com PSS (ver [O TLS público](docs/ICP.md#o-tls-público-icp-4a));
sem retomada de sessão, sem 0-RTT, sem certificado de cliente; e nenhum
atalho na verificação: o `xtask` confere
que nenhum código chama a API `dangerous()` do `rustls` nem escreve um
verificador próprio, e que o kernel não depende do pacote `tls`.

**A bancada é de fora.** O servidor é o **OpenSSL**, pelo módulo `ssl` do
Python do hospedeiro — outra implementação inteira do protocolo —, que o
emulador roda a cada conexão a `10.0.2.100:443`, como roda o `cat` do eco
TCP. Ele escolhe o certificado pelo nome pedido: `bancada.duke` (e
qualquer outro nome, que leva o mesmo certificado), `estranho.duke`, de
outra raiz, `vencido.duke`, vencido em 2021, e `futuro.duke`, que só vale
de 2042 a 2044 — ainda não válido em nenhuma hora que a bancada de tempo
põe, nem no RTC de 2041: é o que mostra que a validade confere o começo
do certificado, e não só o fim. E as cadeias com a forma das públicas,
com um intermediário entre a folha e a raiz: `p384.duke`, `rsa.duke` e
`misto.duke` — a raiz RSA, o intermediário P-384 e a folha P-256, a forma
da cadeia ECDSA da Let's Encrypt pela raiz X1 —, `intruso.duke`, que
manda junto a raiz que o programa não tem, e `falso-p384.duke` e
`falso-rsa.duke`, com a assinatura da folha estragada. A PKI é gerada a
cada máquina em `target/bancada-tls`, fora do repositório; as chaves das
raízes e dos intermediários nem chegam ao disco, e o que vai para a imagem
são só os certificados das três raízes da bancada — a P-256, a RSA de 4096
bits e a P-384 —, em `/dados/tls/bancada.pem`. No hospedeiro, o pacote
`tls` conversa nos testes com o servidor do próprio `rustls` sobre o *ring*
— outro provedor de cifra —, com raízes forjadas com o mesmo nome,
assinaturas trocadas, registros adulterados e transportes que recusam no
meio; e confere contra o cliente do `rustls` sobre o *ring* que uma cadeia
recusada aqui pelo perfil é recusada só pelo algoritmo ou pela chave.

#### O que o exercício encontrou

- **O alerta da recusa não saía.** Quando o programa recusa o
  certificado, o `rustls` deixa o alerta na fila de saída — mas a máquina
  que falhou repete a falha a cada registro que ainda está na entrada, o
  resto do voo do servidor, que chegou junto com o certificado, e só
  transmite a fila quando a entrada acaba. A primeira versão desistia na
  primeira falha repetida, e o servidor via a conexão fechar sem saber
  por quê. O teste do hospedeiro que olha o lado do servidor pegou. Agora
  uma volta que falha e consome um registro conta como progresso.
- **A sessão seguia depois de uma recusa no meio.** O registro que o
  transporte recusou já tinha gastado o número de sequência dele; o
  seguinte sairia com o número errado, e o par o leria como adulterado.
  Agora a sessão fica quebrada com a falha que a quebrou, e cada pedido
  seguinte ouve a mesma recusa sem nada passar pelo transporte.
- **O TLS girava.** Com mais a mandar do que cabia na fila de saída, o
  programa só podia perguntar de novo em laço, e cada volta era uma
  decisão do gate e um registro na auditoria. Daí o envio que espera.
- **O canal perdia o anexo do envio que esperava.** A reexecução tirava
  da porta o que houvesse lá — nada — e recusava o envio por um anexo que
  não confere. Agora o pedido suspenso leva uma cópia, e um caso confere
  que a reexecução pelo canal manda os bytes guardados.
- **A resposta maior que 4 KiB não chegava ao programa.** A cópia da
  resposta para o processo tinha o teto de 4 KiB do tamanho que o processo
  escolhe, e um `net.recv` de 4096 bytes responde, em base64, mais que
  isso. Com uma sessão só, os bytes chegavam aos poucos e a leitura nunca
  enchia; com três sessões ao mesmo tempo, encheu, e a chamada voltou -3.
  O anexo tinha o mesmo teto, abaixo dos 60 KiB que a interface promete.
  Agora a resposta vai inteira, o anexo vai até `MAIOR_ANEXO`, e o
  `guardar` exercita os dois.
- **A segunda espera da leitura vinha sem código.** O `net.recv` que
  recusava a segunda espera respondia só o motivo, e o programa a lia como
  `TECHNICAL_ERROR` — um erro técnico onde o pedido é que não cabia.
  Agora a do envio e a da leitura respondem `INVALID_REQUEST`, como a
  taxonomia da pilha já dizia, com o motivo.

### O canal do agente por TCP

O canal do agente ganha mais um transporte: uma conexão TCP que o kernel
aceita na porta 7070. Nada acima dele mudou — o mesmo aperto IK do Noise,
a mesma chave no registro, o mesmo gate a cada pedido, a mesma auditoria,
os mesmos comandos. São as sessões 5 a 8, uma por **vaga**: quatro
conexões ao mesmo tempo, como as quatro portas do `virtio-console`.

```
$ cargo xtask agent --tcp agent.session
{"jsonrpc":"2.0","id":100001,"result":{"session":5,"transport":"tcp","authenticated":true,"agent":"agente-1","key":"6d991c2d…","role":"operador","since_ms":12820,"remote":"10.0.2.2:55816"}}
```

O cliente é o do `xtask`, com a chave do agente 1 da bancada (`--canal N`
escolhe outra); o par é o do emulador, que leva a conexão do hospedeiro à
máquina.

**A conexão não traz autoridade.** Aceitar uma conexão não é autenticar,
e autenticar não é autorizar: quem chega prova a chave no aperto, e o que
ela pode é o papel que o registro dá a ela. O endereço e a porta do par
não entram em decisão nenhuma — vão para a auditoria, ao lado da chave,
como o que se sabe de por onde a conversa veio. Não há política do TCP: a
mesma decisão que abre uma sessão numa porta abre aqui, e um agente pela
rede tem exatamente a autoridade que teria pela porta — a mesma taxa (o
balde é da chave, e não do transporte), a mesma contenção, a mesma
revogação, a mesma janela de apertos por sessão. A administração é a de
sempre: `admin.challenge` e `admin.execute` pela sessão TCP, com a prova
amarrada ao número dela; o administrador recupera o sistema por qualquer
canal.

**O aperto só termina com a chave confirmada.** A primeira mensagem do IK
pode ser repetida por quem a capturou: o Duke responde, mas quem repete
não abre a resposta, e não escreve um quadro que abra. Numa porta isso não
custa nada — o socket é do hospedeiro. Pela rede, a sessão fantasma
seguraria uma vaga — e diria, a quem lista os agentes e a quem lê a
auditoria, que o dono da chave estava conectado. Por isso, no TCP, o
aperto só termina no primeiro quadro de dados que abre, e só então a
sessão é do agente: para a auditoria, que grava ali o aperto completo;
para `agent.list` e a barra, que só então o contam; e para o firewall, de
quem a conexão passa a ser o fluxo dele. O prazo do aperto — dez segundos
desde a conexão — corre até lá. A sessão que acaba sem a confirmação — o
prazo, um quadro que não abre, a conexão que cai — vai à auditoria como
um aperto recusado, com a chave alegada e o par ("a chave do aperto nao
foi confirmada: o prazo de 10 s venceu (tcp 10.0.2.2:40880, conexao 1)").
Quem conecta e não manda nada cai pelo mesmo prazo ("o aperto nao
veio").

**O firewall.** A escuta deixa entrar só o SYN, e sair só o SYN-ACK ou o
RST — nada mais passa por ela. A conexão aceita é um fluxo como os outros,
do agente que confirmou a chave, e as regras do `net.block` a alcançam: a
que barra o par dela, para o agente dela, derruba a conexão; a sessão
acaba; a auditoria grava a derrubada em nome de quem pôs a regra. A regra
de outro agente, para o mesmo par, não a toca. Como no resto da rede, o
destino é enumerado: a regra nomeia o par inteiro, com a porta dele.

**Contrapressão, e não perda.** Na entrada, a pilha só tira do socket o
que cabe na entrada da vaga (16 KiB): o resto espera no socket, com a
janela do TCP fechada, e quem manda mais depressa do que a sessão atende
espera — numa porta, o que não cabe é perdido e encerra a sessão. Na
saída, com mais de 64 KiB esperando o par ler, a sessão não lê o pedido
seguinte até ele ler; passando de 256 KiB, a resposta não sai e a sessão
acaba, como numa porta. Quem pede e não lê espera, sem perder nada. As
linhas de um mesmo quadro cifrado são atendidas uma atrás da outra, sem a
espera entre elas: quem manda muitas num quadro só é segurado pelo teto.

**O fim.** O par fecha ou cai — o *keep-alive* pergunta a cada 30 s, e
90 s de silêncio derrubam —, uma regra o derruba, ou a sessão acaba por
dentro: a revogação, um quadro que não abre, um aperto recusado. A recusa
em claro sai primeiro, e então o FIN; o fecho tem prazo de cinco segundos,
e passado ele vai um RST — um par que não lê não segura a vaga. O fim de
uma conexão leva só a sessão **dela**, pela geração da vaga, e nunca a da
conexão seguinte, que já pode ter feito o aperto. E as conexões de rede
que o agente abriu são da conexão dele: caem com ela, e a seguinte na
mesma vaga, com a mesma chave, não as herda. O arrendamento também é da
sessão: o que o agente tinha arrendado sai quando a conexão cai, gravado
em nome dele, e quem conecta depois — a mesma chave, inclusive — não
herda nada. O processo que ele lançou pela rede, não: age pela chave, e
não pela conexão — continua o agente depois que ela cai, e perde a
autoridade na hora em que a chave é revogada.

**O NSF observa sem ser autoridade.** Os apertos recusados pela rede vão
à auditoria como os das portas, com o par no detalhe, e o NSF os lê dali,
pelo gate: três falhas da mesma chave alegada são uma observação, dez são
uma detecção de abuso de credencial. Ele não pede nada ao gate por quem
não se autenticou — não há o que conter —, e não há um sensor do TCP fora
do gate.

**A bancada.** O emulador encaminha a porta do canal a uma porta livre do
hospedeiro, só em `127.0.0.1`, escolhida a cada máquina e gravada em
`target/agente-tcp-<arch>.porta`, de onde `cargo xtask agent --tcp` e a
fumaça a leem. A suíte, que roda dentro do kernel, chega ao canal como um
agente de fora: conecta a `10.0.2.100:7070`, um `guestfwd` que roda a
[ponte](xtask/bancada/ponte.py) a cada conexão, e a ponte a leva à porta do
hospedeiro e de volta ao canal — pela pilha do kernel duas vezes, sem
atalho nenhum. Do lado de dentro, a tarefa que atende a vaga é a de
produção, `agent::atender`, andada à mão pela suíte.

#### O que o exercício encontrou

- **O TCP escapava da taxa.** O balde da chave era só das sessões de 0 a
  4; um pedido de uma vaga do TCP não gastava ficha nenhuma, e o programa
  lançado por um agente pela rede gastava do balde do sistema. Agora toda
  sessão de um canal do agente gasta do balde da chave, e o caso `canal
  tcp: a mesma autoridade e a mesma taxa` passa do limite pela rede como
  pela porta.
- **A janela de apertos só conhecia as portas**, e recusava todo aperto
  pela rede como "apertos demais". Ela é por sessão cifrada.
- **A revogação não alcançava a rede.** Ela encerrava as sessões das
  portas da chave revogada; a sessão TCP seguia de pé — recusada pelo gate
  a cada pedido, mas segurando a vaga, e sem a recusa que diz por quê.
  Agora revogar derruba a conexão viva, com a recusa, e o caso o confere
  no meio da conexão.
- **A conexão de rede de um agente pela rede passava à conexão
  seguinte.** O dono de uma conexão aberta por um canal leva a geração do
  transporte, e a de uma vaga TCP era lida como a de uma porta — zero,
  sempre. A conexão seguinte na mesma vaga, com a mesma chave, era o mesmo
  dono: chegando antes da passada do coletor, herdava as conexões da
  anterior, o que nas portas não acontece. Agora a geração é a da vaga.
- **Os agentes pela rede não apareciam** em `agent.list` nem no indicador
  da barra: a atividade só olhava as portas.
- **O fim de uma conexão esquecia a sessão da seguinte.** O fim é tratado
  pelo coletor, depois; se a conexão seguinte na mesma vaga já tinha feito
  o aperto, ele levava a sessão dela. Agora a sessão guarda a geração em
  que o aperto aconteceu, e o fim de uma conexão só esquece a dela.
- **A repetição do aperto segurava uma vaga.** Respondido o aperto, o
  prazo parava, e a sessão fantasma de quem repetiu a primeira mensagem
  ficava na vaga para sempre. Daí a confirmação da chave.
- **E fazia o dono da chave aparecer conectado.** Com o prazo de volta, a
  sessão de quem repete caía em dez segundos — mas, até cair, era contada
  em `agent.list` e na barra como o agente da chave, e a auditoria tinha
  dela um "aperto completo" com o par de quem repetiu. Agora, no TCP, o
  aperto só é gravado e mostrado quando a chave é confirmada, e a sessão
  que acaba antes vai à auditoria como recusada.
- **A escuta não passava pelo firewall.** Ele só deixava entrar quadros de
  conexões da tabela, e o SYN de quem chega ao canal não é de nenhuma. A
  escuta é um fluxo dele agora, que só aceita o SYN.
- **A recusa não chegava.** O transporte era fechado antes de a recusa
  entrar na saída, e o agente via a conexão cair sem saber por quê. Agora
  a recusa entra primeiro, o fecho espera a saída escoar — com prazo —, e
  nada entra na saída depois do fecho pedido.
- **A vaga livre não era só a pendência tratada.** O coletor tirava o fim
  de uma conexão da lista antes de tratá-lo, e quem esperava a lista
  vazia via a vaga livre antes de a sessão ser esquecida e a recusa
  gravada; a suíte pegou. Agora a pendência sai da lista depois de
  tratada.
- **A fumaça contava com a vaga que ainda fechava.** Uma conexão que
  acabou ainda termina o fecho, e um SYN que chega então encontra três
  vagas escutando, e não quatro. `agent.sessions` diz agora se cada vaga
  escuta, e a fumaça espera as quatro antes de conectar quatro agentes.
- **A contrapressão não se mede de fora.** O hospedeiro e o emulador
  guardam alguns MB entre o agente e o kernel, e o agente que não lê na
  fumaça nem enche a saída da vaga. O limiar é conferido na suíte, onde a
  saída da pilha pode ser segurada; a fumaça confere que nada se perde no
  caminho de verdade.
- **A fumaça do tecido pegava o NSF ainda lendo.** O CI reprovou a fumaça
  nas duas arquiteturas na conferência do tecido quieto — quatro registros
  em cinco segundos, e o limite é três. A perna do canal TCP, nova e logo
  antes, escreve centenas de registros em segundos, e o NSF lê no máximo
  uma volta por segundo, com a taxa do papel dele, que numa recusa o faz
  recuar até um minuto. A janela de cinco segundos começa agora quando o
  NSF alcança a cabeça da auditoria — de 1 a 1,6 s depois, nas fumaças
  locais —, e o que se confere continua: alcançada a cabeça, ela para.
  E a falha passou a dizer quem escreveu na janela, o que mostrou a
  segunda causa na rodada seguinte, só no x86: um `lease.expire` da
  serial. A etapa da rede limpava a linha do console com um `set_value`
  — uma edição, que arrenda a linha por sessenta segundos — e não a
  soltava; o vencimento, pelo relógio, caía onde caísse, e com a perna
  TCP passou a cair na janela do tecido. A etapa solta agora a linha que
  editou, e nenhuma deixa um prazo correndo para as seguintes.

### O HTTP de um programa

O HTTP/1.1 é do **programa**, como o DNS e o TLS: o pacote
[`http`](http/src/lib.rs) é um cliente puro, sem dependência nenhuma —
a URL, o pedido, a resposta pela RFC 9112, o *keep-alive* —, e
[`programas::http`](programas/src/http.rs) o põe sobre a conexão do gate,
direto no TCP ou com o TLS no meio, com o nome pelo DNS do próprio
programa. A ordem de uma conexão é a de quem falha fechado:

1. a URL — só `http` e `https`, o host por nome ou IPv4 na forma normal;
2. com `https`, a semente e o relógio, pelo gate, antes de qualquer
   conexão;
3. o nome vira endereço pelo DNS do programa — a associação com o
   servidor, que o gate decide —, e o endereço não vale nada para a
   política;
4. `net.connect` com o destino inteiro, decidido pelo gate como se o
   número tivesse sido digitado, e pelo firewall depois dele;
5. com `https`, o TLS prova o nome da URL pelas âncoras do programa;
6. cada pedido e cada resposta, com cada `net.send` e cada `net.recv`
   decidido de novo, com a autoridade de quem lançou o processo.

```
pagina: http://bancada.duke/ola -> 200 (10 bytes) em 80 ms
pagina: tres pedidos numa conexao so (keep-alive), 1 2 3, e a quarta recusada depois do close
pagina: http://bancada.duke/pedacos -> 200 (22 bytes) em 50 ms
pagina: 65536 bytes foram e voltaram (POST) em 960 ms
pagina: 404 e uma resposta, e 302 volta com o Location, sem ser seguido
pagina: o corpo ate o fecho chegou inteiro, e a conexao nao ficou
pagina: https://bancada.duke:8443/ola -> 200 (TLS13_AES_256_GCM_SHA384) em 110 ms, o aperto em 100 ms
pagina: https://outro.duke:8443/ola -> tls TLS_NAME_MISMATCH em 80 ms
pagina: http://bancada.duke:81/ola -> denied DENY_RESOURCE em 10 ms
pagina: http://bancada.duke/torto/dobra -> protocol HTTP_MALFORMED em 50 ms
pagina: http://bancada.duke/grande/2000000 -> limit HTTP_TOO_LARGE em 50 ms
pagina: http://bancada.duke/corta -> closed HTTP_CLOSED em 80 ms
pagina: http://bancada.duke/mudo -> timeout NETWORK_TIMEOUT em 2010 ms
pagina: eco TCP cru: 65536 bytes foram e voltaram em 880 ms
pagina: http://bancada.duke/grande/65536 -> 65536 bytes em 930 ms (68 KiB/s)
pagina: https://bancada.duke:8443/grande/65536 -> 65536 bytes em 930 ms (68 KiB/s)
pagina: http://bancada.duke/grande/262144 -> 262144 bytes em 3630 ms (70 KiB/s)
```

**As medidas** — no x86, kernel de produção, sozinho na bancada (o
emulador sem aceleração, quatro núcleos; as outras seis respostas
malformadas ficam entre 40 e 100 ms). O TLS custa o aperto, 100 a 170 ms
por conexão, e depois dele nada que se meça: a mesma página de 64 KiB
leva o mesmo tempo clara e cifrada. O HTTP custa menos de 10% sobre o
TCP cru — o `POST` de 64 KiB que vai e volta, contra o eco que faz o
mesmo sem protocolo. A vazão, de 70 a 100 KiB/s, é a da conexão: cada sentido tem
um buffer de 4 KiB, que é a janela do TCP, e cada `net.recv` traz no
máximo um deles e é uma decisão do gate e um registro da auditoria. Na
fumaça inteira, com a página, uma decisão do gate leva 465 µs em média —
a conta da política, 19 µs; um registro da auditoria, 208 µs —, o NSF
usa 2,6% do tempo de máquina e a auditoria 0,5%. Uma visita curta
sozinha leva 550 ms; quatro ao mesmo tempo, de pessoas e de agentes,
1600 ms. No ARM, também release: a página pequena em 70 ms, o aperto em
120 ms, os mesmos 69 KiB/s, e as quatro visitas em 910 ms. O kernel
debug, mais lento, mede mais vazão que o release nas duas arquiteturas —
o gargalo não é a CPU, é o ritmo em que uma janela tão pequena volta a
ser anunciada, assunto da pilha. Na memória, o programa com TLS e HTTP tem uns 700 KB — o TLS
são uns 570, o HTTP uns 60 —; a resposta não passa dos limites de quem
pede (a linha, 8 KiB; a cabeça, 16 KiB; 64 cabeçalhos; o corpo, 1 MiB);
e o kernel guarda 2 × 4 KiB por conexão, quatro por dono, dezesseis na
máquina. (A janela não era o buffer: era um segmento, e é o que o
incremento seguinte mediu e corrigiu — ver [A janela do
TCP](#a-janela-do-tcp).)

**Nada do HTTP é autorização.** O gate decide o destino; o método, o
caminho, o `Host`, os cabeçalhos, o status, o corpo, o redirecionamento e
o *keep-alive* são do protocolo e de quem o fala. Não há comando `http.*`
no registro, nem permissão `http.*` na política, e o kernel não depende do
pacote — o `xtask invariantes` confere as três coisas. O DNS dá um número,
e o número fora do alcance é `DENY_RESOURCE`, como o digitado; o
certificado prova o nome ao programa, e o mesmo destino serve um nome que
o TLS aceita e outro que ele recusa; a conexão mantida não leva
autorização de um pedido ao seguinte. O que o programa pode é o que o gate
decide para os pedidos de rede dele — com a autoridade de quem o lançou,
a pessoa pela sessão ou o agente pela chave, e só ela: a resposta que
chega depois da revogação não é entregue, e a do processo contido também
não.

**As falhas não se misturam.** Cada uma sobe com o código de quem falhou,
e [`http::categoria`](http/src/categoria.rs) diz a família, sem decidir
nada: a recusa do gate (`denied`), a contenção (`contained`), o firewall
(`firewall`), o DNS (`dns`), o transporte — a rede, o teto, a conexão
recusada ou derrubada pelo outro lado (`transport`) —, o prazo
(`timeout`), o TLS (`tls`), a conversa que acabou antes da hora
(`closed`), o protocolo (`protocol`), os limites (`limit`) e o pedido
(`request`). O fim em ordem do outro lado não é falha; a conexão que ele
derruba é `CONNECTION_RESET`, e o servidor que se cala é `NETWORK_TIMEOUT`
— três estados que o transporte dos programas
([`programas::conexao`](programas/src/conexao.rs)) separa, e que o TLS
passa como vieram.

**O protocolo é estreito, de propósito.** Só HTTP/1.1 — e o 1.0 que ele
lê —, um pedido de cada vez numa conexão, sem fila. O fim de linha é CRLF
e nada mais; o cabeçalho dobrado, o `Transfer-Encoding` junto com o
`Content-Length`, dois tamanhos que não concordam e uma codificação que
não é só `chunked` são recusados — cada um deixaria cliente e servidor
lerem respostas diferentes. Os limites — a linha, a cabeça, quantos
cabeçalhos, o corpo — param a leitura ali, e o corpo anunciado grande
demais é recusado sem esperar ele chegar. A conexão só leva o pedido
seguinte quando a resposta teve fim certo, não pediu para fechar e nada
chegou colado depois dela: o que chega sem pedido é um servidor
dessincronizado, e não o começo da resposta seguinte. O prazo é de
silêncio — quanto o outro lado pode ficar sem mandar nada —, e não da
conversa inteira. Fora, de propósito: HTTP/2 e HTTP/3, cookies,
autenticação, *proxy* e seguir redirecionamento sozinho. (A compressão do
corpo, os cookies e o HTTP/2 vieram depois, também no programa — ver [A
compressão do HTTP](#a-compressão-do-http), [Os cookies do
HTTP](#os-cookies-do-http) e [O HTTP/2](#o-http2).)

**A bancada é de fora.** O servidor é um script Python do hospedeiro
([`xtask/bancada/http.py`](xtask/bancada/http.py)), que o emulador roda a
cada conexão a `10.0.2.100:80` — e a `10.0.2.100:8443`, atrás do TLS do
OpenSSL, com os certificados do eco TLS —, com uma rota para cada
comportamento que a suíte e a fumaça conferem: o corpo em pedaços, o
contador da conexão mantida, o eco do `POST`, o lento, o mudo, o que corta,
os malformados. Os dois destinos estão na política de desenvolvimento, e
a porta ao lado não está.

#### O que o exercício encontrou

- **O firewall respondia como a política.** A regra que derruba uma
  conexão viva tirava o número dela da tabela, e o pedido seguinte do
  programa — o envio, ou a leitura que acordou da espera — não achava
  conexão nenhuma: o gate o recusava com `DENY_RESOURCE`, a recusa de um
  recurso que não é de quem pede, quando quem barrou foi o firewall. Um
  caso do TLS conferia exatamente isso, e a documentação dizia o
  contrário. Agora o número continua do dono, cortado: o gate decide o
  pedido como qualquer outro — a autoridade, a contenção e a revogação
  vêm primeiro —, e a execução ouve a regra, `FIREWALL_BLOCKED`, gravada
  como execução da decisão. O `net.close` solta o número, e o coletor o
  esquece quando o dono acaba.
- **O DNS escondia a recusa.** A recusa da associação virava sempre
  `DENY_POLICY`, qualquer que fosse o código do gate, e a recusa na
  pergunta ou na leitura virava `DNS_UNAVAILABLE` — um servidor mudo. O
  programa revogado no meio da cadeia ouvia que o DNS não respondeu. Agora
  a falha leva o código de quem a deu: o do gate, ou o de depois dele.
- **O transporte dos programas misturava três estados.** A conexão
  recusada pelo outro lado e o prazo eram a mesma `TLS_UNAVAILABLE`, e a
  conexão derrubada no meio era o fim em ordem. O transporte saiu do TLS
  para [`programas::conexao`](programas/src/conexao.rs), que o TLS e o
  HTTP usam, e separa a recusa do gate, o código de depois dele, a
  conexão recusada, a derrubada e o prazo.
- **A taxa do papel é o teto da vazão.** Cada `net.recv` traz no máximo
  um buffer da conexão — 4 KiB —, e cada um é uma decisão do gate e um
  registro da auditoria; a que espera e acorda é decidida de novo. Um
  operador, com a taxa de todo dia, ouve `RATE_LIMIT` no meio de uma
  página grande — como deve: a suíte sobe a taxa do operador no caso das
  medidas, e a fumaça as faz pela serial, com a taxa do sistema. (Com a
  janela inteira, um `net.recv` leva 16 KiB, e a mesma página custa um
  décimo das decisões — ver [A janela do TCP](#a-janela-do-tcp). E com o
  plano de dados as leituras e os envios pela conexão aberta não gastam
  mais a ficha: a página passa com a taxa de todo dia, e o caso não a
  sobe mais — ver [O plano de dados](#o-plano-de-dados).)
- **Fechar é um pedido.** O programa que larga uma conexão depois de a
  política tirar o destino dela ouve `DENY_RESOURCE` no `net.close`, e a
  conexão fica na tabela, no teto dele, até ele acabar. O caso da conexão
  mantida achou a de antes no lugar da nova.
- **O NSF parava no primeiro lote da captura.** Os casos do HTTP resolvem
  pelo DNS da bancada, e os do DNS, que vêm depois deles, falharam na
  suíte inteira: o NSF não via resolução nenhuma. Ele lia a captura de um
  servidor em lotes de 16, um lote por volta — e o resto esperava outro
  datagrama, que podia não vir. O NSF recomeçado pela suíte, além disso,
  lia o anel desde o começo: a conversa dos casos de antes enchia o
  primeiro lote, e a leitura parava ali. Agora a volta segue lendo
  enquanto o lote vem cheio, e o NSF que começa do agora só lê a captura
  do agora em diante. O caso `dns: o NSF le a rajada inteira` manda 24
  datagramas entre duas voltas, e confere que a observação recusada não
  insiste.
- **O caso do processo que acaba esperava a tabela, e não a gravação.** O
  coletor tira da tabela as conexões de quem acabou e grava cada derrubada
  em seguida; o caso conferia a gravação assim que a tabela esvaziava, e o
  CI do ARM, com a virtio-gpu, o pegou entre as duas coisas. Os casos mais
  velhos da rede já esperavam a gravação; o do HTTP passou a esperar
  também.

### A janela do TCP

O buffer de cada conexão TCP é de 16 KiB em cada sentido, e é também a
janela que ela anuncia: o outro lado manda até 16 KiB sem esperar
confirmação, e um `net.recv` leva até 16 KiB numa decisão do gate — vários
segmentos do TCP numa decisão, e não um. O `net.send` leva o mesmo, e o TLS
de um programa corta em 16 KiB os registros que manda: um registro, um
envio, uma decisão. O número mora em `protocolo`
(`usuario::nativo::BUFFER_DA_CONEXAO`): o kernel, o transporte dos
programas e o HTTP o usam, e o registro do TLS que não couber num envio
reprova a compilação dos programas.

**O que a medida achou.** A vazão de 70 KiB/s da fase 12 não era o buffer de
4 KiB, nem a decisão do gate por leitura — a explicação que este texto deu.
A janela anunciada era de **um segmento**, 1474 bytes: a placa dizia ao
`smoltcp` que recebia um quadro por vez (`max_burst_size`), e ele limita a
janela à rajada da placa, para o outro lado não mandar mais do que ela tem
onde pôr. Com um segmento de janela, o outro lado manda um e espera a
confirmação; a de um segmento só é atrasada — 10 ms no `smoltcp`, num
relógio de tiques de 10 ms —, e a conexão andava um segmento a cada 20 ms,
qualquer que fosse o buffer. A captura do fio (`DUKE_CAPTURA`, ver
[Depuração](#depuração)) mostrou exatamente isso: por página de 64 KiB, 45
segmentos de 1460 bytes, um a cada 19,98 ms (mediana), cada pausa inteira
entre o dado e a confirmação do hóspede; e o programa lendo 43 vezes, 1524
bytes em média. Só com a rajada corrigida, o buffer ainda de 4 KiB, a
mesma página levou 90 ms em vez de 920. E o enigma da fase 12 — o kernel
debug, mais lento, media mais vazão que o release — era o mesmo: com um
segmento de janela, quem lia mais devagar juntava mais segmentos por
leitura. Com a janela inteira, o release voltou a ser o mais rápido.

**A rajada é a da placa.** A placa pendura dezesseis buffers de recepção, e
diz ao `smoltcp` que recebe dezesseis quadros de uma vez — o que é verdade:
são dezesseis lugares para o dispositivo escrever antes de a pilha colher.
Uma asserção de compilação amarra os dois números: a rajada, em
segmentos, cobre o buffer de uma conexão, e a janela é o buffer inteiro. O
emulador segura o quadro que não cabe até a placa ter lugar, mas uma placa
de verdade o perderia: a rajada anunciada é a que o dispositivo aguenta, e
não a que a bancada perdoa. A janela cabe nos 16 bits do TCP — outra
asserção —, sem escala.

**As medidas**, na fumaça, uma rodada cada; antes, o código da fase 13.1:

| | x86 release | x86 debug | ARM release | ARM debug |
|---|---|---|---|---|
| janela anunciada | 1474 → 16 384 bytes | o mesmo | o mesmo | o mesmo |
| `GET` de 64 KiB | 920 ms (69 KiB/s) → 80 ms (800 KiB/s) | 730 (87) → 300 (213) | 810 (79) → 80 (800) | 930 (68) → 170 (376) |
| `GET` de 256 KiB | 3490 (73) → 120 (2133) | 2680 (95) → 640 (400) | 3370 (75) → 130 (1969) | 2750 (93) → 760 (336) |
| `GET` de 64 KiB, cifrado | 810 (79) → 130 (492) | 900 (71) → 380 (168) | 810 (79) → 130 (492) | 920 (69) → 330 (193) |
| `POST` de 64 KiB, ida e volta | 880 → 70 | 870 → 280 | 900 → 70 | 1000 → 390 |
| eco TCP de 64 KiB, ida e volta | 880 → 50 | 940 → 430 | 860 → 50 | 940 → 420 |
| eco TLS | 12 222 bytes em 240 ms → 49 086 em 70 ms | 12 222 em 160 → 49 086 em 280 | 12 222 em 180 → 49 086 em 80 | 12 222 em 170 → 49 086 em 300 |
| decisões do gate da página | 984 → 288 | → 309 | 952 → 288 | → 307 |
| pico do heap na fumaça | 1729 → 1750 KiB | → 1763 KiB | 1761 → 1774 KiB | → 1800 KiB |

O eco TLS manda três registros cheios, e o registro cresceu de 4 KiB para
16: quatro vezes os bytes em menos tempo. O `GET` de 256 KiB leva 17
leituras em vez de 177; a fumaça inteira, 1575 decisões em vez de 2271.

**A memória.** Os dois buffers de uma conexão nascem com ela e saem com ela:
32 KiB por conexão, 128 KiB por titular, 512 KiB do heap de 8 MiB com a
tabela cheia — eram 128 KiB. A suíte confere a conta: doze conexões tomam
os dois buffers de cada uma e pouco mais, e fechadas o heap volta. A
associação UDP continua com 4 KiB em cada sentido — um datagrama tem no
máximo 1472 bytes —, e a suíte confere que ela não acompanha o TCP. A placa
usa 64 KiB de frames físicos, fora do heap, para os dezesseis buffers de
recepção. E o heap ganhou o pico (`peak_bytes` no `heap.stats`), que a
fumaça escreve: na fumaça inteira, o mesmo antes e depois, porque o pior
momento do heap não é o das conexões.

**O gate não muda.** Cada `net.send` e cada `net.recv` continua decidido,
com a autoridade de quem pede; a revogação, a contenção e o firewall valem
no pedido seguinte; cada um vai para a auditoria, com o destino. O que
muda é quantos pedidos uma transferência custa — e a taxa dos papéis, que
a página grande esgotava, deixou de ser gasta pelos dados no incremento
seguinte: ver [O plano de dados](#o-plano-de-dados).

**A contrapressão** é a do TCP: o buffer cheio fecha a janela, e o que não
coube fica do outro lado — o kernel guarda o buffer, e nada além. A suíte
o vê no fio: a janela de 16 KiB anunciada, a janela zero quando ninguém lê,
e a janela inteira de volta na leitura que leva o buffer numa decisão; e
quatro fios trocam 64 KiB cada, ao mesmo tempo, em quatro leituras cada um.

**O que fica de fora.** O HTTPS ficou no TLS: perto de 500 KiB/s no x86, o
AES-GCM em software, que a vazão nova deixou à mostra — é o incremento das
otimizações de cifra. A confirmação atrasada continua num relógio de 10 ms:
o fim de uma rajada ímpar ainda espera um tique. A pessoa que lê pelo
Terminal uma leitura inteira em base64, uns 22 KiB, passa do anel de 16 KiB
da janela, e o que não cabe é contado como perdido, como qualquer saída
grande — `max` limita a leitura. E 32 KiB por sentido foram medidos e não
ficaram: a página de 256 KiB foi de 150 para 140 ms, as decisões da fumaça
de 1580 para 1556, e o pior caso do heap dobraria.

### O plano de dados

A taxa do papel limita o **exercício de autoridade**: abrir uma conexão,
associar um destino, abrir um arquivo, lançar um processo, mandar uma
mensagem, administrar. Até este incremento ela limitava também cada envio e
cada leitura por uma conexão já aberta — a decisão de um `net.recv` gastava
a mesma ficha que a do `net.connect`. A medida, antes de mudar, mostrou o
que isso fazia com a política padrão:

- **a taxa de segurança era um teto de vazão.** Um MiB custa perto de 85
  decisões do gate — uma por leitura de até 16 KiB, mais os envios, as
  esperas, a conexão e o fecho —, e os 50 pedidos por segundo do operador,
  com rajada de 100, deixavam passar uns 1,2 MiB de uma vez. Uma pessoa
  operadora trazendo 8 corpos de 1 MiB ouvia `RATE_LIMIT` em todos;
- **a recusa era falha, e não contrapressão.** O `RATE_LIMIT` no meio de uma
  transferência autorizada a derrubava: o programa não tinha o que fazer
  com ele;
- **a recusa vazava capacidade.** O `net.close` também era recusado pela
  taxa, a conexão ficava aberta até o processo acabar, e depois de quatro —
  o teto do titular — toda conexão nova era `RESOURCE_LIMIT`;
- **quanto mais rápida a máquina, mais cedo a recusa.** A mesma carga, mais
  depressa, precisa de mais rajada: o ARM da bancada, mais rápido neste
  trabalho, era recusado antes do x86.

O plano de controle das mesmas cargas — conexões, sementes do TLS, relógio,
âncora — usava no máximo 15 da rajada de 100, e não crescia com o tamanho da
transferência. O que pressionava a taxa era o plano de dados.

**O que muda é o orçamento, e só ele.** Cada comando declara o plano dele
no registro (`plano`, e `plane` no `agent.describe`), como declara a
permissão — um comando sem a linha não compila: `control`, o exercício de
autoridade; `data`, o `net.send` e o `net.recv`; `release`, o `net.close`. O
pedido de dados continua uma decisão do mesmo gate, com a mesma
identidade, a mesma autoridade, a mesma política, a contenção, o firewall,
a posse e a validade da conexão, e o registro na auditoria; o que ele deixa
de fazer é gastar a ficha do papel — e só quando é o que diz ser: uma
operação sobre um recurso **já aberto, vivo, de quem pede**, com quem pede
não contido, **e autorizada pela política**. Fora disso o pedido é um
exercício de autoridade como outro qualquer, e paga a ficha:

| o pedido de dados | o orçamento |
|---|---|
| pela conexão aberta, viva, de quem pede, autorizado | a capacidade: o recurso e o caminho da auditoria |
| pela conexão de outro titular | a taxa, e a recusa do gate (`DENY_RESOURCE`) |
| por um número que não é conexão nenhuma | a taxa, e a recusa do gate (`DENY_RESOURCE`) |
| recusado pela política, pela revogação, pela confiança no código | a taxa, decidida a recusa |
| de um processo, agente ou pessoa contido | a taxa, e `DENY_CONTAINED` ou `DENY_CREDENTIAL` |
| pela conexão que o firewall cortou | a taxa, e `FIREWALL_BLOCKED` depois do gate |
| o fecho da conexão aberta ou cortada, de quem pede, não contido | nenhum: o fecho nunca espera e nunca paga |

O orçamento é estimado antes da decisão, para a taxa valer na mesma ordem
de sempre, e confirmado depois dela: a recusa — da política, da revogação,
do papel que sumiu — volta à taxa e gasta a ficha. Não há uma segunda
política nem um segundo mecanismo de autorização: o plano só escolhe de
onde sai o orçamento da decisão que o gate tomou.

**O fecho não fica preso.** O `net.close` da conexão de quem pede não gasta
ficha nem espera o caminho da auditoria: a taxa gasta não prende o recurso
aberto. O da conexão que o firewall cortou também — fechá-la devolve a vaga
ao titular. O contido não tem esse orçamento: fechar, para ele, é exercício
de autoridade, e a contenção o recusa.

**A capacidade da auditoria.** Toda decisão do gate vira um registro no
anel da auditoria, de 1024 registros, e o journal os leva para o disco. Um
registro que sai do anel antes do journal é auditoria perdida — o journal
grava a lacuna no lugar dele. Sem a ficha, o plano de dados precisa de
outro freio, e é este: o **atraso**, da cabeça da auditoria ao que o
journal já gravou ([`oleoduto.rs`](kernel/src/oleoduto.rs)):

- abaixo de 640 registros (cinco oitavos do anel), todos passam;
- de 640 a 768, a **partilha**: passa quem tem pendentes menos registros de
  dados que a parte justa — 640 divididos pelos principais com registros
  pendentes —, e quem passou da parte espera;
- de 768 para cima, todo pedido de dados que pode esperar espera.

**Esperar é a espera da fase 9.2.** O pedido com `wait` não é decidido, não
é gravado e não é executado: quem o despachou — o fio do canal, o dos
processos, o interpretador — o guarda, como guarda a leitura que espera
dados, e o coletor do journal, que normalmente grava a cada dois segundos,
não dorme enquanto alguém espera. Quando o journal grava, ou o prazo do
`wait` vence, **o pedido inteiro passa pelo gate de novo** — identidade,
autoridade, política, contenção, firewall e auditoria de agora: a
revogação, a contenção e o firewall de enquanto ele esperava valem para
ele. Nada aqui recusa um pedido por volume: o prazo vencido decide o pedido
na margem.

**A margem** é a quarta parte do anel, de 768 ao fim, para o que não espera:
a reexecução de quem esperou — uma por pedido suspenso, e eles são no
máximo um por fio, por porta e por console —, o fecho — no máximo um por
conexão aberta —, e o exercício de autoridade, que a taxa limita. O pedido
de dados **sem** `wait`, com o caminho cheio, não pode esperar, e não passa
de graça: volta à taxa, como qualquer pedido.

**As contas** estão em `security.metrics`, na seção `budget`: as decisões
de cada plano, as recusas por taxa, os pedidos de dados que voltaram à
taxa e os que passaram na margem; as esperas pela auditoria (adiadas,
acabadas, as tarefas esperando agora, quanto duraram); o atraso dela (a
cabeça, o de agora, o maior desde o boot, o do journal, os registros
perdidos e os limiares); a vazão (os bytes mandados e lidos pelo plano de
dados); e a justiça — o índice de Jain das decisões de dados recentes entre
os principais, a parte do maior, e a conta de cada um.

**As medidas.** O mesmo `medidor` da medida de antes de mudar — 16 páginas
de 64 KiB, 8 corpos de 1 MiB e 2 de 1 MiB cifrados —, pela mesma pessoa
operadora e pelo sistema, com a política padrão, em release; cada código
numa rodada sozinha na bancada, antes e depois alternados — três pares no
x86, um no ARM (o menor e o maior das três, no x86):

| | x86, antes | x86, depois | ARM, antes | ARM, depois |
|---|---|---|---|---|
| operador, 16 × 64 KiB | 1 MiB, 467–522 KiB/s | 1 MiB, 467–517 KiB/s | 768 KiB, 4 `RATE_LIMIT` | 1 MiB, 764 KiB/s |
| operador, 8 × 1 MiB | **nenhum**: 8 `RATE_LIMIT` | 8 MiB, 2320–2445 KiB/s | **nenhum**: 8 `RATE_LIMIT` | 8 MiB, 2536 KiB/s |
| operador, 2 × 1 MiB cifrados | **nenhum**: 2 `RATE_LIMIT` | 2 MiB, 1119–1402 KiB/s | **nenhum**: 2 `RATE_LIMIT` | 2 MiB, 1312 KiB/s |
| sistema, 16 × 64 KiB | 476–550 KiB/s | 459–517 KiB/s | 800 KiB/s | 819 KiB/s |
| sistema, 8 × 1 MiB | 1878–2307 KiB/s | 2301–2651 KiB/s | 2388 KiB/s | 2668 KiB/s |
| sistema, 2 × 1 MiB cifrados | 1119–1183 KiB/s | 1150–1197 KiB/s | 1055 KiB/s | 1393 KiB/s |
| o gate, média por decisão, sistema (≈944 decisões) | 294 µs | 280 µs | 358 µs | 324 µs |

O sistema, que tem taxa de sobra, é a medida do custo novo: a mesma vazão
e a mesma latência do gate para a mesma carga, dentro da variação de uma
rodada para outra — a estimativa do orçamento e a conta do caminho não
aparecem. Cada rodada do operador são 89 decisões de controle, 828 de
dados e 26 de fecho: o controle cabe na rajada de 100 do papel, e não
cresce com o tamanho. Com o journal levando a auditoria, como fora da
suíte, o operador faz 2027 a 2584 KiB/s, e o maior atraso do caminho fica
entre 283 e 365 registros: abaixo da partilha, nenhuma espera.

Na fumaça — o kernel de produção, o agente da porta 2, do papel
`operador`, o journal e o NSF de verdade —, o `vazao` traz os 5 MiB em 2,9
s no x86 release (2133 KiB/s claro, 1204 KiB/s cifrado) e em 2,7 s no ARM
release (2275 e 1190 KiB/s), e a `carga` passa o seu MiB por quatro
conexões em 1,1 a 1,2 s: 610 decisões de dados e 9 de fecho, nenhuma
recusa por taxa no sistema todo, nenhuma espera, o maior atraso da
auditoria entre 247 e 271 registros, nenhum perdido, e o NSF saudável
depois. O controle do `vazao` — as conexões, as sementes do TLS, o
relógio, a âncora — são 24 decisões, medidas na suíte.

**O que fica de fora.**

- **A margem não segura tudo.** Os 256 registros de margem são para a
  reexecução de quem esperou, o fecho e o exercício de autoridade — e este
  último é limitado pela taxa de cada papel, e não pela margem: a soma das
  rajadas de todos os papéis passa dela (só a do sistema é 800). Uma
  rajada de controle de muitos principais com o journal parado ainda
  empurra registros para fora do anel antes do disco, como antes deste
  incremento; o journal grava a lacuna, e `budget.audit_backlog.lost` a
  conta. A contrapressão nova segura o volume de dados, que era o que
  crescia sem teto além da taxa.
- **A justiça é aproximada.** A conta separa dezesseis principais; os
  seguintes dividem uma linha, e a parte justa deles é a de um só. A parte
  é contada em registros pendentes, e não em bytes: quem lê 16 KiB por
  decisão e quem manda um byte por decisão pesam o mesmo no caminho da
  auditoria — que é o que a partilha protege.
- **Sem fila entre quem espera.** Quando o journal grava, todos os que
  esperam acordam e são decididos de novo; quem chega primeiro ocupa o
  lugar. A justiça vem da parte de cada principal, e não da ordem de
  chegada.
- **O NSF pode ficar para trás.** Ele lê até 512 registros por volta, uma
  volta por segundo, e não é consumidor do caminho: o gate não sabe que ele
  existe. Com os dados fora da taxa, a auditoria pode crescer mais depressa
  que isso; o NSF que fica para trás se declara degradado (`audit-gap`), e
  o que ele não leu está no journal.
- **Sem journal, sem contrapressão.** Com a persistência fora do ar, a
  auditoria fica só no anel, como sempre ficou, e o caminho não segura
  ninguém: o anel guarda as últimas 1024 decisões, e uma transferência
  grande as ocupa.
- **Na prática, a contrapressão só se arma com o journal parado.** O
  journal grava a cada dois segundos, ou com meio anel pendente, e
  acompanha o que a bancada consegue produzir — o maior atraso medido na
  fumaça está acima. A suíte a exercita com o journal seguro de propósito
  e com um consumidor simulado.
- **O pedido de dados sem `wait`**, com o caminho cheio, volta à taxa, e
  com a ficha esgotada ouve `RATE_LIMIT`, como antes. O transporte dos
  programas ([`programas::conexao`](programas/src/conexao.rs)) manda e lê
  sempre com `wait`.
- **O DNS** abre uma associação UDP por resolução — um exercício de
  autoridade, que gasta a ficha —, e os datagramas dela são o plano de
  dados.
- **As taxas padrão não mudaram.** O que mudou é o que gasta a ficha.

### A compressão do HTTP

O corpo comprimido é do **programa**, como o resto do HTTP: o pedido diz o
que o cliente decodifica (`Accept-Encoding`), a resposta diz o que o
servidor aplicou (`Content-Encoding`), e o pacote `http` decodifica no
processo — `gzip` (e `x-gzip`) e `deflate` —, com um teto que quem pede fixa
antes de descomprimir ([`codificacao.rs`](http/src/codificacao.rs)). O
gate não vê nada disso: decide a conexão, cada envio e cada leitura pelo
destino e por quem pede, e os bytes que passam são bytes, comprimidos ou
não — com TLS, nem os bytes.

```
compressao: http://bancada.duke/bomba/gzip/512 -> limit HTTP_TOO_LARGE
compressao: a bomba de 512 MiB parou no teto de 4 MiB; o monte foi de 64 a 8192 KiB
compressao: http://bancada.duke/comprimido/gzip/6291456 -> limit HTTP_TOO_LARGE
compressao: http://bancada.duke/comprimido/gzip/65536 -> gzip: 65536 bytes de 12767 no fio
compressao: http://bancada.duke/comprimido/deflate/65536 -> deflate: 65536 bytes de 12755 no fio
compressao: http://bancada.duke/comprimido-ate-fechar/gzip/65536 -> gzip: 65536 bytes de 12767 no fio
compressao: https://bancada.duke:8443/comprimido/gzip/65536 -> gzip: 65536 bytes de 12767 no fio
compressao: http://bancada.duke/negocia/65536 aceitando gzip=false deflate=true -> deflate (12755 bytes no fio)
compressao: http://bancada.duke/negocia/65536 aceitando gzip=false deflate=false -> identity (65536 bytes no fio)
compressao: tres respostas comprimidas numa conexao so
compressao: http://bancada.duke/estragado/desconhecida -> protocol HTTP_UNACCEPTED_ENCODING
compressao: http://bancada.duke/estragado/crc -> protocol HTTP_CORRUPT_CONTENT
compressao: http://bancada.duke/estragado/cortado-fecho -> protocol HTTP_CORRUPT_CONTENT
compressao: http://bancada.duke/estragado/vazio -> o conteudo vazio
compressao: http://bancada.duke/comprimido/gzip/4718592 -> limit HTTP_TOO_LARGE
compressao: http://bancada.duke/comprimido/gzip/4718592 com um teto de 8 MiB: 4718592 bytes de 879856 no fio
compressao: http://bancada.duke:81/comprimido/gzip/1000 -> denied DENY_RESOURCE
```

**Transparente para a autorização.** A compressão não é recurso,
permissão nem regra, e o gate não decide nada por ela — nem para deixar,
nem para recusar. O programa que comprime não faz pedido nenhum que o HTTP
já não fizesse, e a mesma página, pedida como é, em gzip e em deflate,
passa pelas mesmas decisões, na mesma ordem — o nome pelo DNS, a conexão,
o envio, as leituras, o fecho —, cada uma deixada em nome de quem pediu: o
que muda é quantas leituras o corpo pede, sete como é e três ou quatro
comprimido, para 64 KiB de texto. Nenhum registro da auditoria tem o nome
de uma codificação, um cabeçalho dela ou um caminho do HTTP — a suíte e a
fumaça leem a auditoria registro a registro para conferir —, e o `xtask
invariantes` confere que o kernel e a política não falam de codificação de
conteúdo. A revogação, a contenção e o firewall no meio de um corpo
comprimido chegam com o código deles: metade do gzip lida, a leitura
seguinte é a recusa, e nada da metade é entregue — nem decodificada, nem
como um gzip cortado no lugar da recusa.

**A negociação.** O pedido aceita as duas por padrão
([`Aceitas`](http/src/codificacao.rs)); quem não quer diz `identity`, e não
deixa de mandar o cabeçalho — sem ele, o servidor poderia mandar qualquer
uma (RFC 9110, 12.5.3). O `Accept-Encoding` é escrito pelo pacote, como o
`Content-Length`: quem chama não o põe à mão, e o que o pedido aceita é o
que o cliente decodifica. A resposta numa codificação que o pedido não
aceitou, numa desconhecida — `br`, `zstd`, `compress` — ou em duas
empilhadas é `HTTP_UNACCEPTED_ENCODING`, conferida pela cabeça, antes de
ler o corpo: o comprimido não é entregue como se fosse o conteúdo. A
resposta sem corpo — a um `HEAD`, um `204`, um `304` — não tem o que
decodificar; o corpo vazio é o conteúdo vazio. Os cabeçalhos ficam como
vieram, e a resposta diz o que o cliente tirou (`codificacao`) e o tamanho
no fio (`no_fio`).

**Os limites, antes de descomprimir.** O corpo como veio passa pelo limite
do corpo (1 MiB) enquanto chega, e o anunciado grande demais é recusado
sem ser lido. O que sai do decodificador tem um teto próprio, o do corpo
decodificado (`Limites::descomprimido`, 4 MiB por padrão), fixado antes do
primeiro byte sair: a saída cresce dobrando, em potências de dois do teto,
e para nele com `HTTP_TOO_LARGE`. O tamanho que o gzip anuncia no fim é
conferido, e não reserva nada. As tabelas do DEFLATE são fixas, uns 8 KiB,
e a janela de 32 KiB é a própria saída. A memória de uma decodificação é o
corpo que veio, as tabelas e a saída — no pior instante, quando a saída
dobra, uma vez e meia o teto. A bomba — meio GiB de zeros em uns 500 KiB, a
maior razão do formato — custa o teto e para: o monte do processo foi de
64 KiB a uns 8 MiB, os pedaços que a saída deixou para trás inclusive, que
o monte de um programa não devolve. O trabalho é linear na entrada e na
saída.

**O que se confere.** No gzip (RFC 1952): a assinatura, o método, os bits
reservados, os campos opcionais, o CRC da cabeça, o DEFLATE, e o CRC-32 e
o tamanho de cada membro; membros seguidos são o formato, cada um com a
janela dele, e depois do último nada. No `deflate`, o formato zlib (RFC
1950): o método, a janela, o `FCHECK`, sem dicionário preestabelecido, o
DEFLATE e o Adler-32; o DEFLATE cru que servidores antigos mandam como
`deflate` é recusado — o cliente não adivinha. No DEFLATE (RFC 1951), o que
a RFC proíbe e o zlib recusa. O que não confere é `HTTP_CORRUPT_CONTENT` —
cortado, corrompido, com a soma errada, com bytes a mais —, da família do
protocolo: a mensagem chegou, e o conteúdo dela não se lê. A conexão em
que isso acontece não leva outro pedido.

**Escrito aqui.** O pacote `http` não depende de ninguém — o `xtask`
confere desde a fase 12 —, e o DEFLATE é dele também
([`inflar.rs`](http/src/inflar.rs)). A confiança nele vem de três lados que
não dependem dele: vetores do zlib, gerados pelo Python e guardados como
bytes; um escritor de teste que monta os blocos símbolo a símbolo — todo
comprimento, toda distância, códigos de até 15 bits, e cada bloco que a RFC
proíbe —, com a referência em aplicar os símbolos, sem Huffman; e somas
publicadas. Cada corte de cada corpo é `Cortado`; cada um dos 21 616 bits
trocados é recusado ou não muda o conteúdo — os 290 que passam caem fora
do que as somas cobrem, como a hora e o nome do gzip —; e o monte do teste
é medido, a bomba inclusive.

**As medidas.** O texto da bancada — palavras de um vocabulário pequeno,
como o de uma página — vai a 18,7% em gzip: 1 MiB são 195 890 bytes no
fio, e 64 KiB, 12 767 (12 755 em deflate). O `compressao` traz 1 MiB dele
como é e em gzip, três vezes cada, claro e cifrado, na fumaça — o kernel de
produção, a pessoa operadora, a política padrão —, em release, cada fumaça
sozinha na bancada, quatro no x86 e duas no ARM (o menor e o maior):

| 1 MiB de texto | como é | gzip |
|---|---|---|
| x86, claro | 530–800 ms | 300–430 ms |
| x86, cifrado | 860–980 ms | 370–490 ms |
| ARM, claro | 550–610 ms | 300–380 ms |
| ARM, cifrado | 870–1000 ms | 380–440 ms |

Os tempos vão do pedido ao conteúdo decodificado e conferido, e incluem a
bancada gerar o texto a cada pedido — uns 90 ms no hospedeiro — e, no
gzip, comprimi-lo, uns 50 ms. O que se ganha é o fio: cinco vezes menos
bytes pelo TCP, pelo TLS e pelas leituras do gate, que custam por byte; o
decodificador, no processo, custa menos que isso. Com o kernel de teste em
debug, em que cada leitura custa mais, a diferença cresce: no ARM, 3,1 s
contra 1,1 s claro, e 4,9 s contra 1,2 s cifrado. O programa inteiro — a
bomba, as páginas, a negociação, o estragado, o teto e as medidas — leva
de 16 a 18 s na fumaça; três dele ao mesmo tempo, de duas pessoas e de um
agente, 22 s na suíte do ARM em release. No hospedeiro, o decodificador faz
uns 200 MiB/s de gzip de texto, metade disso no CRC-32; a bomba de 512 MiB
para no teto de 4 MiB em 2,3 ms; e um MiB de blocos dinâmicos mínimos — o
pior trabalho por byte de entrada — leva uns 140 ms.

**O que não é comprimido ficou como estava.** Os programas que falam HTTP
cresceram de 5 a 13 KiB — o DEFLATE, as somas e a negociação; o `vazao` do
x86, de 683 a 696 KiB —, e cada pedido leva o `Accept-Encoding`, 32
bytes. Na fumaça, em pares de antes e depois alternados na mesma árvore —
quatro no x86 e dois no ARM —, o `vazao` traz os 5 MiB em 2,94–3,23 s
depois e 2,87–3,07 s antes no x86, e em 2,62–2,71 s depois e 2,73–2,83 s
antes no ARM; a `carga`, que não é HTTP, faz o seu MiB em 1,00–1,12 s
depois e 0,98–1,48 s antes no x86, e em 1,15–1,28 s e 1,06–1,29 s no ARM. A
mesma árvore importa: o caminho dela entra nos binários — o kernel, com o
mesmo código, sai com um `.bss` de outro tamanho em cada árvore —, e a
primeira rodada, com o antes e o depois em árvores diferentes, mediu até
30% a mais que era da árvore, e não do código: o código novo numa árvore
nova repetiu a diferença, e na mesma árvore do antes ela sumiu.

**O que fica de fora.**

- **Brotli e zstd.** Avaliados, e deixados. Os dois comprimem texto melhor
  que o gzip, e nenhum entra sem pesar: o pacote `http` não tem
  dependências, e um decodificador de Brotli escrito aqui seria várias
  vezes o DEFLATE, com um dicionário de uns 120 KiB embutido em cada
  programa que fala HTTP; o do zstd também é maior, e o HTTP deixa o
  servidor anunciar uma janela de até 8 MiB (RFC 9659). A bancada tampouco
  os gera: o Python dela não tem nenhum dos dois na biblioteca padrão.
  Quando um motivo pesar mais que isso, entram aqui, no programa, com o
  mesmo teto antes de descomprimir, e o gate continua sem saber.
- **O pedido não é comprimido.** O corpo de um `POST` vai como é: quase
  nenhum servidor aceita um pedido comprimido sem combinar antes.
- **O `Transfer-Encoding` comprimido** continua recusado, como antes: o
  cliente não manda `TE`, e só o `chunked` é enquadramento.
- **Faixas e compressão.** Um pedido de faixa (`Range`) pede o pedaço da
  representação codificada, e um pedaço de gzip não se decodifica: quem
  pede faixas pede sem codificação (`Aceitas::NENHUMA`).
- **O corte na fronteira de dois membros** do gzip não se vê: o primeiro
  membro é um gzip inteiro. É o formato; o `Content-Length` e o fecho do
  TLS são o que diz que a mensagem acabou.
- **O custo da entrada hostil** é linear, e não desprezível: um MiB de
  blocos dinâmicos mínimos, que não escrevem nada, custa uns 140 ms no
  hospedeiro, cada bloco montando as tabelas dele — no processo de quem
  pediu, e limitado pelo corpo.
- **O CRC-32 é metade do custo** de decodificar um gzip, um byte por vez —
  candidato do incremento de otimizações.
- **O teto é de cada resposta**, e quem o sobe aceita a memória; e o monte
  do programa não devolve páginas, de modo que o que a bomba custou fica
  mapeado até o processo acabar.

### Os cookies do HTTP

Um cookie é o estado que um servidor pede para o **programa** guardar e
mandar de volta — e é do programa, como o resto do HTTP. Ele mora num pote
na memória do processo ([`Pote`](http/src/cookies.rs)), com as regras da
RFC 6265 e da 6265bis, e não é credencial do Duke: prova alguma coisa ao
servidor, e nada aqui. O kernel não o vê, o gate decide pelo destino e por
quem pede, e a revogação, a contenção e o firewall valem no pedido
seguinte, leve ele a sessão ou não.

```
cookies: http://bancada.duke entrou (sessao 4f0c9e1d2a7b), o privado a reconheceu, e depois de sair nao
cookies: https://bancada.duke:8443 entrou (sessao 9a51c37e08d2), o privado a reconheceu, e depois de sair nao
cookies: a sessao de um pote nao foi por outro pote, por um pedido sem pote, nem a http://estranho.duke
cookies: o Secure so foi por https, e a origem clara nao o sobrescreveu
cookies: Domain=duke e Domain=estranho.duke recusados; o Path so vale dentro dele
cookies: os prefixos valeram; do proprio site s1,s2,s3,__Host-a, navegando de outro s2,s3,__Host-a, buscando para outro s3
cookies: o programa nao criou, nao sobrescreveu e nao viu o HttpOnly
cookies: o Max-Age=5 venceu no relogio do sistema; o Expires passado apagou, o futuro ficou
cookies: 60 cookies num dominio ficaram 50 no pote; o de 4100 bytes nao entrou
cookies: entrar, privado, sair e privado numa conexao so: 200 200 200 401
cookies: http://bancada.duke:81/cookies/privado com a sessao no pote -> denied DENY_RESOURCE
```

**Do programa, e de nenhum outro.** O pote é um valor que o programa cria
(`Pote::novo()`) e passa a cada troca (`trocar_com_pote`, `buscar_com_pote`):
o pedido leva o `Cookie` que o pote dá para ele, e os `Set-Cookie` da
resposta vão para o pote — e saem dos cabeçalhos que o programa vê. Sem
pote, nada de cookie, e o `Cookie` é escrito só pelo pacote: quem chama
não o põe à mão. Não há pote global. Dois potes do mesmo processo não se
veem; dois processos — da mesma pessoa, de duas pessoas, de uma pessoa e
de um agente — têm cada um a sua memória, e a página que o kernel dá a um
processo chega zerada, de modo que nada do pote de um processo que acabou
chega ao seguinte. O filho de um `bifurcar` é uma cópia do processo — o
pote junto —, e herda a autoridade dele: é o programa que se copia. E
nada se guarda além do processo: o pote acaba com ele.

**Não é identidade, nem autoridade.** Quem pede é o processo, com a
autoridade de quem o lançou — a pessoa pela sessão, o agente pela chave
—, e o registro da auditoria diz essa pessoa ou esse agente, nunca um
cookie; um servidor não muda a autoridade de nada com um `Set-Cookie`. A
suíte confere pelos dois lados: uma pessoa e um agente, cada um com o seu
processo e a sua sessão na bancada, não veem a do outro, e cada decisão
sai em nome de quem lançou; e o mesmo pedido ao privado da bancada, sem
sessão e com ela, passa pelas mesmas decisões, na mesma ordem — o que muda
é só a resposta. Com a sessão no pote, a chave revogada leva o pedido
seguinte a `DENY_ROLE`, a contenção a `DENY_CONTAINED`, e a regra do
firewall a `FIREWALL_BLOCKED`, antes de um byte sair; liberado, o processo
segue com a mesma sessão, que lá fora nunca deixou de valer para o
servidor — aqui ela não abria nada. Nenhum registro tem o cabeçalho, a
sessão ou um caminho dos cookies: a suíte e a fumaça leem a auditoria
registro a registro — a fumaça procura também os identificadores das
sessões que o programa disse —, e o `xtask invariantes` confere que o
kernel e a política não falam de cookie.

**As regras.** O domínio: sem `Domain`, o cookie é só do host que o deu;
com ele, de quem está abaixo do domínio, que tem de conter o host —
`Domain=duke`, de um rótulo só, é de todo mundo, e é recusado sem uma
lista de sufixos públicos —, e um host por endereço só tem cookie dele
mesmo. O caminho: sem `Path`, o diretório do pedido, e o `/cookies` vale
em `/cookies/eco`, e não em `/cookiesx`. O `Secure` só vem e só vai por
`https`, e uma origem clara não sobrescreve um cookie seguro de mesmo
nome. O `HttpOnly` só vem pela rede: a API do programa não o cria, não o
sobrescreve e não o vê — o valor vai para o fio, e não para o programa;
nem um `{:?}` do pote mostra valor nenhum, para um log não levar uma
sessão junto. O
`SameSite` segue o contexto que quem pede declara: do próprio site, tudo
vai; de outro site, o `Strict` não vai, o `Lax` — o padrão — só numa
navegação com `GET` ou `HEAD`, e o `None`, que exige `Secure`, sempre; e
a resposta a um pedido de outro site que não é navegação não põe `Strict`
nem `Lax`. Os prefixos: `__Secure-` exige `Secure`, e `__Host-` também,
sem `Domain` e com `Path=/`. A validade: o `Max-Age` vence o `Expires`, em
qualquer ordem, zero ou menos apaga, e nenhuma passa de 400 dias; a data
é lida pela RFC 6265, a que não existe é ignorada. Os tetos: 4096 bytes
de nome e valor, 50 cookies por domínio, 300 no pote e 128 KiB; o que
passa tira primeiro os vencidos, depois o usado há mais tempo do domínio
que passou, depois o usado há mais tempo de todos. O cabeçalho vai do
caminho mais longo ao mais curto, e entre os iguais, do mais antigo.

**O relógio.** A validade se confere na hora do TLS, pela mesma regra —
o civil autenticado, ou o tempo lógico sem ele, e nunca o RTC cru (ver
[Os consumidores da hora](#os-consumidores-da-hora)) —: o `system.info`,
pelo gate, lido uma vez por troca e só quando um cookie com validade está
em jogo — algum que iria no pedido, ou algum `Set-Cookie` da resposta. A
hora confere a validade e mais nada: o cookie não é identidade,
credencial, autoridade nem permissão. Sem relógio — sem RTC, num programa
cujo manifesto não declara `system.read`, ou com a leitura recusada pelo
gate —, o que já tem validade no pote não vai, porque não há como saber se
venceu, e a resposta diz quantos ficaram (`retidos`); o que chega com
validade fica de sessão — dura o pote, isto é, no máximo o processo —, e
o `Max-Age=0` apaga do mesmo jeito.

**A bancada.** O servidor HTTP da bancada ganhou `/cookies`: `entrar` dá
uma sessão `HttpOnly` e `SameSite=Lax` — `Secure` no `https` —, assinada
com um HMAC de uma chave tirada da da bancada; `privado` só responde a
quem a traz, com o identificador dela; `sair` a apaga; `eco` devolve o
`Cookie` que chegou; `definir` devolve os `Set-Cookie` que o programa
pede; e `muitos` manda dezenas deles de uma vez. O `cookies` confere tudo
isso de dentro, claro e cifrado, e o `buscador` ganhou o pote, para a
suíte interromper a sessão no meio.

**As medidas.** No hospedeiro, com um transporte de mentira que devolve
sempre a mesma resposta numa conexão mantida, uma troca custa 593 ns sem
pote e 595 ns com o pote vazio; com uma sessão no pote, 932 ns; com ela
renovada a cada resposta por um `Set-Cookie` de `Max-Age` — uma leitura
do relógio por troca —, 1,98 µs; com 50 cookies do domínio no cabeçalho,
2,4 µs; e com 300 de outros hosts, que não vão, 2,1 µs: o pote é uma
lista, e o que limita a busca é o teto dela. No sistema, o `cookies` faz
40 trocas numa conexão mantida com o `eco` da bancada, três vezes — sem
pote, com uma sessão e com um cookie de `Max-Age` —, na fumaça, em
release:

| 40 trocas | sem pote | sessão | `Max-Age` |
|---|---|---|---|
| x86, quatro fumaças | 110–130 ms | 110–150 ms | 180–220 ms |
| ARM, três fumaças | 120–140 ms | 120–170 ms | 170–250 ms |

O relógio do sistema anda de 10 em 10 ms, e a mesma série varia de uma
rodada para outra até um milissegundo por troca: a sessão fica nesse
ruído — em média, menos de meio milissegundo por troca. O `Max-Age` custa
uns 2 ms por troca (de 0,8 a 3,3), e é a leitura do relógio: o
`system.info` pelo gate — uma decisão, um registro na auditoria, e uma
resposta com o estado do sistema inteiro; com o kernel de teste em debug,
de 5 a 18 ms. O programa inteiro faz uns 627 pedidos ao gate — 41
conexões, 277 leituras e 55 leituras do relógio, do TLS e dos cookies —
e leva de 8,7 a 10,2 s na fumaça em release, e de 15 a 17 s em debug;
três dele ao mesmo tempo, de duas pessoas e de um agente, 10,5 s na
suíte do ARM em release, e 13 s na do x86.

**O que não usa o pote ficou como estava.** O kernel e a política não
mudaram — só a suíte. O `buscador`, que ganhou o pote, cresceu 33 KiB no
x86 e 31 KiB no ARM; o `cookies` tem 725 KiB no x86 e 730 KiB no ARM; e
os outros programas que falam HTTP mudaram menos de 9 KiB, para mais ou
para menos. Na fumaça, em pares de antes e depois alternados na mesma
árvore, três no x86 e dois no ARM:

| | x86 antes | x86 depois | ARM antes | ARM depois |
|---|---|---|---|---|
| `vazao`, 5 MiB | 2,44–2,75 s | 2,45–2,65 s | 2,31–2,52 s | 2,30–2,33 s |
| `carga`, 1 MiB por 4 conexões | 0,98–1,31 s | 0,95–1,33 s | 0,92–1,17 s | 0,91–0,98 s |
| `pagina` inteira | 4,66–4,92 s | 4,87–5,11 s | 3,75–4,03 s | 3,96–4,03 s |

As faixas se sobrepõem. A rodada do depois mais lenta na `pagina`, no
x86, foi a mais lenta de todas também na `carga`, que não é HTTP; e na
`pagina`, que não usa o pote, o que mudou é o `Cookie` entre os
cabeçalhos reservados.

**O que fica de fora.**

- **Guardar além do processo.** O pote acaba com o processo. Guardá-lo
  pediria um lugar no armazém que fosse só de um titular — de uma pessoa,
  ou de um agente —, e os escopos do armazém são do papel, e o
  `/armazem/compartilhado` é de todos os operadores: um cookie guardado ali
  seria lido por qualquer um deles. Um escopo por titular seria uma
  abstração nova, e não entrou.
- **A lista de sufixos públicos.** Sem ela, só o domínio de um rótulo é
  recusado: um `Domain=co.uk` vindo de `a.co.uk` seria aceito. Na rede da
  bancada não há sufixo público de dois rótulos; numa rede de verdade, a
  lista entra aqui, no programa.
- **O site do pedido é declarado.** Sem um navegador, não há documento de
  onde o pedido sai: quem pede diz se é do próprio site ou de outro, e se
  é uma navegação, e o `SameSite` vale por isso. O padrão é o próprio
  site.
- **O cookie sem nome** da 6265bis (`Set-Cookie: abc`) é recusado, e o
  `Partitioned`, a prioridade e o `SameParty` não existem aqui.
- **O relógio custa uma decisão.** Cada troca com um cookie de validade em
  jogo faz um `system.info` pelo gate — um registro na auditoria, e uma
  ficha da taxa de quem lançou o programa, a sessão da pessoa ou a chave
  do agente: a do caminho de controle, que o plano de dados não cobre.
  Num experimento fora da árvore, o `cookies` de uma pessoa operadora fez
  400 trocas seguidas com um cookie de `Max-Age`, numa conexão mantida —
  umas 300 por segundo: a taxa do papel, 50 pedidos por segundo com
  rajada de 100, recusou o relógio a partir da troca 116, e 243 das 400
  foram sem o cookie (`retidos`), o que o servidor vê. E, enquanto a taxa
  não voltava, os outros pedidos de controle dos programas daquela sessão
  ouviram `DENY_RATE` também: o `system.uptime` do próprio programa, no
  experimento, e uma conexão TLS nova, que lê o mesmo relógio, não se
  abriria. Três processos — de duas pessoas e de um agente —, com 400
  trocas cada um ao mesmo tempo, não chegaram à taxa: cada um gasta a
  sua. A segurança não cede — sem relógio, o que tem validade não vai —;
  cede a conversa. Um relógio que o programa lesse sem uma decisão do
  gate, ou a leitura dele no orçamento do plano de dados, seria uma
  abstração nova, e não entrou.
- **O servidor enche o pote.** Até o teto de cada domínio e do pote, e o
  que passa tira o usado há mais tempo — de outro domínio também, quando o
  pote inteiro está cheio. E um host pode pôr cookies do domínio de cima,
  que vão também aos vizinhos dele, num `Cookie` de dezenas de KiB que o
  vizinho pode recusar. É o que acontece num navegador; a defesa é o teto,
  que é de cada processo, e o que se perde é a conversa desse programa
  com esses hosts.

### O HTTP/2

O HTTP/2 é do programa, como o HTTP/1.1: o pacote `http` fala a RFC 9113,
com o HPACK da RFC 7541 ([`ClienteH2`](http/src/h2.rs)), pelo TLS quando o
ALPN o escolhe, ou no claro com conhecimento prévio (h2c). Ele multiplexa
pedidos, e não autoridade: várias correntes numa conexão são vários
pedidos do mesmo processo, pela mesma conexão que o gate decidiu pelo
destino, e cada envio e cada leitura dela continuam decididos com a
autoridade de quem o lançou. O kernel não sabe que as correntes existem.

```
correntes: h2c com conhecimento previo: 200 Http2
correntes: 8 ao mesmo tempo de 1 byte a 100 KiB em 110 ms, e a lenta em 310 ms
correntes: o eco de 200 KiB voltou inteiro
correntes: gzip decodificado, e a sessao da bancada pelo pote
correntes: 2 MB passam do limite: HTTP_TOO_LARGE so na corrente, e a conexao segue
correntes: reiniciada e recusada so na corrente: HTTP_STREAM_RESET HTTP_STREAM_REFUSED
correntes: 16 trocas numa conexao so
correntes: a conexao acaba inteira, a outra corrente junto: HTTP_MALFORMED HTTP_MALFORMED HTTP_TOO_MANY_FRAMES HTTP_CONNECTION_ENDED
correntes: o ALPN: Http2 Http2, Preferir2 Http2, Http1 Http11; antigo: Preferir2 Http11, Http2 HTTP_MALFORMED; claro: Preferir2 Http11
correntes: 40 pedidos, no maximo 16 guardados: HTTP_TOO_MANY_STREAMS, e a mais antiga recebida antes da seguinte
correntes: medida 40 pedidos de 1 KiB, em ms: http/1.1 160, h2 um a um 180, h2 juntos 160
correntes: http://bancada.duke:81 pelo HTTP/2 -> denied DENY_RESOURCE
correntes: tudo conferiu
```

**Multiplexar pedidos, e não autoridade.** Uma corrente não é uma
conexão, um titular nem uma decisão. O `correntes` inteiro, de uma pessoa
operadora, faz catorze conexões — nove ao servidor claro e cinco ao
cifrado, uma decisão `net.connect` para cada — e manda dezenas de
correntes por elas, sem nenhuma decisão a mais por corrente; tudo é
deixado em nome da pessoa, menos a porta fora do alcance,
`DENY_RESOURCE`, antes do primeiro byte. A suíte interrompe as correntes
no meio — a segunda parada na metade do corpo, a terceira ainda por vir —:
a chave revogada do agente que lançou o programa faz a leitura seguinte
`DENY_ROLE`, gravada com a chave dele; o processo isolado ouve
`DENY_CONTAINED`, pelo TLS; a regra do firewall derruba as duas conexões
claras do processo, e as correntes ouvem `FIREWALL_BLOCKED`. Em cada um,
a conexão acaba inteira, e as duas correntes que esperavam ouvem o mesmo
código, como veio — nem um erro do HTTP/2 no lugar da recusa, nem metade
de uma resposta. Três `correntes` ao mesmo tempo, de duas pessoas e de um
agente, têm cada um as suas conexões, as suas correntes e as suas tabelas
do HPACK, e cada decisão sai em nome de quem lançou. Nenhum registro tem
o HTTP/2 — nem uma pseudo-cabeça, nem o prefácio, nem um caminho das
correntes —, e o `xtask invariantes` confere que o kernel e a política
não falam dele.

**O que se recusa.** O que é da corrente fica nela: a resposta
malformada — os pseudo-cabeçalhos fora do lugar, o nome em maiúsculas, um
cabeçalho da conexão, o `:status` que não é de três dígitos, o `101`, a
informativa que acaba a corrente, os dados antes da cabeça, o corpo que
não confere com o `content-length`, os *trailers* sem o fim —, o corpo
além do limite, e o `RST_STREAM` do servidor (`HTTP_STREAM_RESET`, ou
`HTTP_STREAM_REFUSED`, que pode ir noutra conexão); o cliente manda o
`RST_STREAM` dele, e a conexão segue. O que quebra o protocolo acaba com
a conexão inteira, com o `GOAWAY` e o código da RFC: o quadro torto, a
corrente que o servidor abre, o bloco de cabeça que não se decodifica — a
tabela dinâmica é da conexão —, o `PUSH_PROMISE` (o *push* vai desligado),
o `SETTINGS` fora da faixa, a janela que transborda, e as enxurradas:
1024 quadros seguidos sem levar resposta nenhuma adiante, 64
`CONTINUATION` num bloco, ou um bloco cru maior que o dobro do limite da
cabeça. O `GOAWAY` do servidor recusa as correntes acima da última, e o
fecho com erro chega como `HTTP_CONNECTION_ENDED`.

**A memória tem teto.** Uma conexão guarda 16 correntes — as abertas e as
que acabaram e não foram recebidas —; a seguinte é
`HTTP_TOO_MANY_STREAMS`, e quem chama recebe uma antes de abrir outra. A
janela de cada corrente é 64 KiB: é o que uma corrente parada segura. A
esperada abre de uma vez até o limite do corpo dela, e um byte além, para
o corpo grande demais ser visto como tal. A janela da conexão, 16 MiB, é
reaberta quando cai à metade: o teto é o das correntes. A cabeça conta
como o HPACK conta, e a tabela dinâmica continua certa mesmo quando a
lista passa do limite.

**O HPACK.** O decodificador inteiro: a tabela estática, a dinâmica, o
Huffman — as tabelas transcritas de duas implementações independentes e
conferidas entre si —, e os vetores do apêndice C da RFC 7541. O
codificador não indexa nada: o primeiro bloco põe a tabela deste lado,
no servidor, em zero bytes, e nenhum ajuste do servidor pede
atualização depois; o `cookie`, o `authorization` e o
`proxy-authorization` vão como nunca indexados, para ninguém no caminho
os guardar.

**O ALPN e o h2c.** Quem conecta escolhe (`Protocolo`): `Http1`, como
sempre; `Preferir2`, que no `https` oferece `h2` e `http/1.1` e fala o que
o servidor escolher; e `Http2`, que exige o HTTP/2 — no `https`, o
servidor que não o escolhe é recusado, depois do aperto, com
`HTTP_MALFORMED`; no `http`, o prefácio com conhecimento prévio. O
`Upgrade` do HTTP/1.1 para o h2c não existe: a RFC 9113 o tirou. O TLS
ganhou a oferta e a leitura da escolha (`Sessao::conectar_com_protocolos`,
`Sessao::protocolo`); o destino é o mesmo, e o gate não a vê.

**A validação.** Os testes do pacote conversam com um servidor de mentira
que respeita as janelas do cliente e com roteiros hostis — cada recusa,
com o código e o alcance dela —, e com o `nghttpd`, a referência da
nghttp2: as trocas, a tabela dinâmica, a janela pequena, o corpo grande,
os *trailers*, o servidor que não fala HTTP/2 e o `GOAWAY` deste lado. Um
teste que precisa do `nghttpd` falha sem ele, e a CI o instala. Na
bancada, o servidor HTTP/2 é um script do hospedeiro
([`xtask/bancada/http2.py`](xtask/bancada/http2.py)), conferido com o
`curl`; e o `antigo.duke`, o mesmo destino por outro nome, faz o papel do
servidor que só fala HTTP/1.1.

**As medidas.** No hospedeiro, só o protocolo — o cliente contra um
servidor de mentira na memória, sem rede, com 1 KiB de corpo —, uma troca
custa de 740 a 850 ns pelo HTTP/1.1 numa conexão mantida, de 920 a 940 ns
pelo HTTP/2 uma de cada vez, e de 975 a 990 ns com dezesseis correntes
juntas: os quadros e o HPACK custam uns 150 ns por troca, e na memória não
há ida e volta para economizar. No sistema, o `correntes` faz 40 pedidos
de 1 KiB à bancada pelo HTTP/1.1 numa conexão mantida, pelo HTTP/2 um de
cada vez, e pelo HTTP/2 tantos ao mesmo tempo quanto a conexão guarda —
na fumaça, em release:

| 40 pedidos de 1 KiB | HTTP/1.1 | HTTP/2 um a um | HTTP/2 juntos |
|---|---|---|---|
| x86, cinco fumaças | 140–280 ms | 150–290 ms | 160–320 ms |
| ARM, quatro fumaças | 180–330 ms | 280–490 ms | 160–200 ms |

O que se mede é o hóspede. Na captura do fio, a bancada responde em meio
milissegundo; o custo de cada pedido é o caminho dele no Duke — um
`net.send` e um `net.recv`, cada um uma decisão do gate, a espera, a
cópia —, e não o protocolo. Juntas, as correntes não economizam
decisões: cada pedido ainda é um envio. Economizam espera: oito correntes
de 1 byte a 100 KiB acabam juntas em 110 a 220 ms, e a que o servidor
segura 300 ms acaba em 290 a 370 ms, sem segurar as outras. No x86, as
três séries ficam na mesma faixa; no ARM, onde a volta do hóspede varia
mais, juntas são a mais estável. O programa inteiro faz uns 430 pedidos
ao gate — 14 conexões, 200 envios e de 178 a 190 leituras — e leva de 3,7
a 4,7 s na fumaça do x86, e de 3,7 a 4,1 s na do ARM.

**O que não fala HTTP/2 ficou como estava.** O kernel e a política não
mudaram — só a suíte —, e o HTTP/1.1 é o mesmo código. Na fumaça, em
pares de antes e depois alternados na mesma árvore, três no x86 e dois
no ARM:

| | x86 antes | x86 depois | ARM antes | ARM depois |
|---|---|---|---|---|
| `vazao`, 5 MiB | 4,09–4,35 s | 3,85–4,03 s | 3,80–4,22 s | 3,98–4,02 s |
| `carga`, 1 MiB por 4 conexões | 1,42–1,59 s | 1,56–1,73 s | 1,51–1,74 s | 1,50–1,76 s |
| `pagina` inteira | 6,53–6,64 s | 6,17–6,42 s | 4,91–5,58 s | 5,06–5,13 s |
| `compressao` inteiro | 22,0–22,9 s | 22,3–23,5 s | 22,9–23,2 s | 21,5–22,1 s |
| `cookies` inteiro | 11,3–11,8 s | 10,8–11,7 s | 10,3–10,7 s | 10,3–11,2 s |

As faixas se sobrepõem ou se tocam, e quando uma série do depois sai à
frente, outra sai atrás. A máquina destas medidas é mais lenta que a das
medidas dos cookies — lá, a `vazao` levava de 2,4 a 2,8 s no x86 —, e por
isso os pares são de uma sessão só, e não comparados com os números de
antes.

**O que o exercício encontrou.**

- *A bancada escrevia um quadro por escrita.* A cabeça e o corpo de cada
  resposta iam em segmentos separados, e o segundo esperava o ACK
  atrasado do primeiro (Nagle): 44 ms por troca, 200 trocas em 8,8 s no
  hospedeiro. A bancada passou a juntar o que produz numa escrita, como
  um servidor de verdade: 200 trocas em 41 ms, e no emulador, os 40
  pedidos um a um caíram de 2520 para 880 ms (x86, debug). O cliente
  estava certo — uma escrita por pedido, uma leitura por resposta.
- *O programa abria mais correntes que a conexão guarda.* O teto de 16
  é do desenho, e a medida do `correntes` engolia a falha calada; agora
  ela respeita o teto e diz o código quando um envio falha.
- *A fumaça lia o fim do programa anterior.* O `cookies` sai com o mesmo
  código, e a perna do HTTP/2 o achava na cauda do log; ela passou a ler
  só os registros depois do lançamento.
- *A linha do ALPN não cabia num registro do log* (160 bytes), e saía
  cortada.
- *Cada conexão da bancada compilava o `http2.py`* — 15 ms por processo,
  o HTTP/1.1 junto. Agora só a conexão que fala HTTP/2 o importa.
- *A medida do ARM variava, e não era do HTTP/2.* Uma fumaça deu 490 ms
  para os 40 pedidos um a um pelo HTTP/2, contra 180 pelo HTTP/1.1; a
  seguinte, 280 contra 330. A captura do fio (`DUKE_CAPTURA`) mostrou
  onde estava o tempo: a bancada responde em meio milissegundo
  (mediana), nos dois protocolos, e o resto é do hóspede — de 3,6 a 4,8
  ms de mediana entre a resposta chegar e o pedido seguinte sair, com
  voltas isoladas de 10 a 60 ms, que caem numa série ou na outra. Nada a
  corrigir no HTTP/2; o custo da volta no hóspede do ARM fica medido, e
  não explicado.

**O que fica de fora.**

- **O HTTP/3.** É outro incremento do roteiro, e depende do QUIC sobre o
  UDP, que começa por uma avaliação.
- **O *push*, a prioridade, o `CONNECT` estendido e o `Upgrade`.** O
  *push* vai desligado no prefácio, e um `PUSH_PROMISE` acaba com a
  conexão; a prioridade é lida e ignorada, como a RFC 9113 deixa; o
  `CONNECT` estendido (RFC 8441), que levaria o WebSocket, não existe; e
  o `Upgrade` do HTTP/1.1 para o h2c a RFC tirou.
- **Uma conexão por origem.** Dois nomes no mesmo servidor, mesmo com um
  certificado que cubra os dois, são duas conexões — dois nomes no DNS,
  dois destinos no gate. Juntá-los numa conexão faria a decisão de um
  destino valer para um nome que o gate não viu.
- **O corpo inteiro na memória.** Como no HTTP/1.1, a resposta chega
  inteira, até o limite dela; quem chama não a lê em pedaços. A janela de
  cada corrente segura o servidor, e o limite segura a corrente.
- **O cliente não manda `PING`.** Responde os do servidor; a conexão
  parada cai pelo prazo do transporte, como no HTTP/1.1.
- **Os ajustes são do código.** As 16 correntes, a janela de 64 KiB e a
  cabeça mudam por `ClienteH2::com`; os programas usam o padrão.
- **Os *trailers* são conferidos e largados**, como no HTTP/1.1.
- **O pedido não usa a tabela dinâmica.** Nada deste lado entra na tabela
  do servidor: o pedido vai pela tabela estática e pelo Huffman, e um
  pedido repetido custa os mesmos bytes — em troca, este lado não deixa
  estado nenhum no servidor para ele guardar.
- **A bancada atende num fio só.** O `http2.py` intercala as respostas
  quadro a quadro, dentro das janelas, mas não mede um servidor que
  responde em paralelo de verdade.
- **O programa cresce.** Cada programa que fala HTTP pelo
  `programas::http` leva o cliente HTTP/2, mesmo o que só fala HTTP/1.1:
  o protocolo se escolhe ao conectar. No x86, de 40 a 50 KiB a mais — o
  `buscador`, que ganhou as rotas do HTTP/2, 50 KiB —, e no ARM, de 33 a
  46 KiB; os que não falam HTTP mudaram menos de 1 KiB. O `correntes` tem
  761 KiB no x86 e 771 KiB no ARM. Deixar o HTTP/2 só em quem o pede
  seria uma escolha de compilação no `programas`, e não entrou.

### As mutações da rede

Quinze mutações contra o que este incremento promete — a posse, a
permissão antes da existência, o alcance enumerado, quem acabou, os tetos,
o caractere partido, a decisão antes do uso, o observador do ARP e o fio
que faz a pilha andar —, cada uma contra a suíte de quatro núcleos (no x86,
e no ARM onde o caminho é dele) ou, a da forma normal, contra os testes da
política no hospedeiro: **quinze reprovadas**.

| Mutação | Reprovada por |
|---|---|
| a posse ignorada: o número basta para achar a conexão | `rede: a conexao e de quem a abriu` — outro titular usou uma conexão que não é dele |
| a existência antes da permissão | `rede: o destino e o recurso` — quem não tem `net.connect` soube que a conexão não existe |
| o alcance não confere: qualquer destino é discado | o mesmo caso, `rede: a politica nova vale para a conexao aberta` e `rede: o programa disca pelo gate` |
| o coletor não varre as conexões (ARM) | `rede: a conexao de quem acabou e derrubada` |
| a geração da porta ignorada no dono | `rede: o agente que sai perde as conexoes` |
| a pessoa que saiu continua viva | `rede: a conexao de quem acabou e derrubada` |
| o processo morto continua vivo | o mesmo caso |
| os fechos não contam no teto de quem fechou | `rede: quem fecha ainda ocupa a sua vaga` |
| o começo de um caractere fica preso | `rede: o caractere partido nao prende a leitura` |
| `net.connect` sem conferir a decisão | `rede: o handler so age no que foi decidido` — discou sem a decisão do gate |
| o uso da conexão sem conferir a decisão | o mesmo caso — mandou por uma conexão sem a decisão |
| o ARP sem o observador | `rede: ARP vai e volta` — nenhuma resposta chegou |
| sem teto por titular | `rede: o teto de conexoes e por titular` |
| sem o fio da rede | `rede: a pilha tem endereco pelo DHCP`, e os doze casos seguintes |
| o zero à esquerda aceito no destino | `endereco::testes::o_ambiguo_e_recusado` |

E cinco contra o que a matriz e o CI deste incremento corrigiram — **cinco
reprovadas**:

| Mutação | Reprovada por |
|---|---|
| o driver não confere a geração ao enfileirar | `agentes: o quadro de uma conexao nao sai na seguinte` — a resposta ao aperto de uma conexão que caiu saiu na seguinte |
| a resposta do aperto sem a geração | o mesmo caso, pelo mesmo motivo |
| a recusa do aperto sem a geração | o mesmo caso — a recusa da conexão que caiu saiu na seguinte |
| a volta à imagem e a reposição da suíte sem a ordem das gravações | a conferência de `reaplicar`, na primeira reposição: "reposicao do journal sem a ordem das gravacoes" |
| o teto da espera de transmissão de volta a cem mil voltas (ARM, release) | seis casos da rede, a placa desligada logo depois do DHCP — é a reprodução da falha do CI |

A mutação do ARP rodou primeiro com outras duas máquinas na bancada, que
tem quatro processadores, e reprovou também cinco casos de tela com prazo;
repetida sozinha, só os dois do ARP.

### As mutações da espera

Vinte e sete mutações contra o que a leitura que espera promete — quem
acorda, quando acaba, quem pode suspender, a decisão de novo na entrega,
uma espera por conexão, a ordem do canal, o console que segura a entrada,
e as três tarefas que esperam de verdade —, contra os casos da rede da
suíte de quatro núcleos, no x86, e contra a fumaça as que só o kernel de
produção alcança: **vinte e seis reprovadas, e uma equivalente**.

| Mutação | Reprovada por |
|---|---|
| a reexecução no canal pode suspender de novo | `rede: o canal espera sem perder a ordem` — depois do prazo a sessão não respondeu |
| a reexecução do processo pode suspender de novo | `rede: o programa disca pelo gate` — o programa ficou sem resposta |
| a reexecução no console pode suspender de novo | `rede: o console espera e segura a entrada` — depois do prazo o console não mostrou a leitura |
| o contexto do comando permite suspender sempre | `rede: a espera vence no prazo` — a leitura sem permissão de esperar suspendeu |
| largar a espera não a desarma | o mesmo caso — a conexão ficou presa à espera largada |
| duas esperas na mesma conexão | `rede: uma espera por conexao` |
| o waker não fica no socket | `rede: a espera acorda pelo evento da pilha`, e mais dois casos |
| o dado não acaba com a espera | `rede: a espera acorda pelo evento da pilha` — acordada, a espera não viu o dado |
| a mudança de estado não acaba com a espera | `rede: a espera acaba com a conexao` — a derrubada pelo outro lado |
| o prazo não acaba com a espera | `rede: a espera vence no prazo` |
| o canal não adia o que veio atrás do pedido suspenso | `rede: o canal espera sem perder a ordem` — a sessão respondeu enquanto o pedido esperava |
| a geração não confere antes da reexecução | o mesmo caso — o pedido de quem saiu foi respondido ao seguinte |
| o console confirma outra linha enquanto espera | `rede: o console espera e segura a entrada` |
| o console que fecha não larga o comando | o mesmo caso |
| o Terminal que espera lê a entrada | o mesmo caso |
| o físico que espera lê o teclado | o mesmo caso |
| a entrega do processo decidida com outra autoridade | `rede: o programa disca pelo gate` — a entrega não saiu em nome de quem lançou o programa |
| o envelope do pedido suspenso sai | `rede: o canal espera sem perder a ordem` |
| suspende com o dado já na conexão | `rede: a espera acorda pelo evento da pilha` |
| suspende numa conexão fechada | `rede: a espera acaba com a conexao` |
| espera o que já mudou, sem o estado dito ao dono | `rede: a espera e pelo que ainda nao se sabe` — o aperto já terminado esperou |
| a tarefa da sessão do canal não deixa o waker no socket | `rede: as tarefas acordam pelo evento` |
| a tarefa dos programas não deixa o waker no socket | o mesmo caso |
| a tarefa da sessão do canal sem o relógio (fumaça) | a leitura da serial no silêncio não voltou |
| o interpretador sem o relógio (fumaça) | o console não voltou da leitura no prazo |
| o interpretador não deixa o waker no socket (fumaça) | o console só voltou no prazo, e não pelo eco |

Três delas sobreviveram na primeira rodada, e cada uma mostrou um caso que
não olhava o que devia. A da geração: o caso fechava a porta antes de
reabrir, e o fecho já apaga a sessão — a resposta não tinha por onde sair;
o caso passou a reabrir sem o aviso do fecho, como o kernel vê quando os
dois chegam juntos, e com a sessão de quem saiu ainda na tabela só a
geração separa os dois clientes. As duas das tarefas que esperam: na
fumaça o eco quase sempre chega antes de a leitura armar, e nenhuma
espera precisava do evento; na suíte, sem executor, quem atende confere a
cada volta. O caso `rede: as tarefas acordam pelo evento` faz o papel do
executor: consulta os futuros das duas tarefas com um waker que conta, e
confere que é o eco que os acorda — e só ele.

A equivalente: tirar só a conferência de `suspender` não muda nada,
porque o handler pergunta `pode_suspender` antes de armar. A que quebra a
permissão na origem — o contexto que permite sempre — é a quarta da
tabela.

### As mutações do UDP

Trinta mutações contra o que a associação promete — só o destino, o
datagrama inteiro, o teto do quadro, a fila, a porta própria, o socket que
sai da pilha, a espera e o protocolo como parte do destino —, contra os
casos da rede da suíte de quatro núcleos, no x86, e as da política também
contra os testes dela no hospedeiro: **trinta reprovadas**.

| Mutação | Reprovada por |
|---|---|
| o filtro de origem não filtra | `rede: o datagrama de outra origem nao chega` — um alheio acabou a espera |
| o filtro só confere o endereço | o mesmo caso — o de outra porta acabou a espera |
| o filtro só confere a porta | o mesmo caso — o de outro endereço acabou a espera |
| a volta da pilha não descarta o alheio | o mesmo caso — o alheio acabou a espera |
| o desenho anterior: só quem lê ou espera descarta | o mesmo caso — o alheio ficou na fila esperando uma leitura |
| o alheio descartado não é contado | o mesmo caso |
| o consumo tira o que estiver na frente | `rede: o datagrama nao se corta` — tirou um datagrama que não foi o entregue |
| o consumo não confere a origem | `rede: o datagrama de outra origem nao chega` — tirou o alheio que esperava atrás |
| o consumo não confere o tamanho | `rede: o datagrama nao se corta` |
| o datagrama maior que `max` é cortado | o mesmo caso |
| o datagrama maior que `max` é tirado e perdido | o mesmo caso — o que devia ficar não chegou |
| a entrega não tira o datagrama | `rede: o datagrama vai e volta inteiro` — o primeiro bloco veio de novo |
| `net.send` sem o teto | `rede: o datagrama nao se corta` — 1473 bytes saíram |
| o teto oito bytes mais largo | o mesmo caso — com a constante errada, 1473 bytes saíram |
| o teto exclusivo | o mesmo caso — 1472 bytes não saíram |
| a fila de saída cheia aceita e perde calado | `rede: a fila cheia recusa o datagrama` |
| duas associações vivas na mesma porta | `rede: a associacao tem a sua porta` |
| fechar deixa o socket na pilha | o mesmo caso — sobrou um socket de ninguém |
| fechar desliga o socket e o deixa na pilha | o mesmo caso |
| a derrubada deixa o socket na pilha | `rede: a associacao de quem acabou e derrubada` |
| o waker não fica no socket UDP | `rede: o datagrama de outra origem nao chega` — o injetado nem acordou a espera |
| a associação nunca tem o que ler | o mesmo caso — o do destino não acabou a espera |
| a associação não espera | o mesmo caso — a leitura vazia não suspendeu |
| o teto por titular só conta TCP | `rede: o teto conta as associacoes` |
| `udp:` lido como TCP | `endereco::testes::o_protocolo_separa_os_destinos`, `a_forma_normal`, e a política padrão deixa de se ler — vinte e três testes |
| a forma normal sem o protocolo | os mesmos |
| a forma normal sem o protocolo, contra a imagem | o `xtask`, antes de montar a imagem: a política dela não se lê |
| a decisão compara o destino sem o protocolo | `testes::a_matriz_aprovada` — o operador alcançou `udp:10.0.2.100:7` |
| a mesma, contra a suíte | `rede: o destino e o recurso` — o sistema abriu `udp:10.0.2.100:7` |
| o `discador` sem a perna UDP | `rede: o programa disca pelo gate` |

Desenhá-las mostrou quatro casos que não olhavam o que deviam; e reler o
desenho enquanto elas rodavam mostrou um defeito, que pôs a primeira
rodada de lado — as trinta da tabela rodaram sobre o código corrigido:

- **O alheio ocupava a fila do destino.** Descartado só quando alguém lia
  ou esperava, ele ficava na fila enquanto ninguém lia, e oito deles — a
  fila inteira — faziam o `smoltcp` jogar fora o datagrama seguinte do
  destino. Reproduzido no desenho anterior: com a fila cheia de alheios, o
  bloco do TFTP se perdeu. Agora a volta da pilha descarta o alheio da
  frente de cada associação, debaixo da mesma trava, logo depois de
  receber; quem lê ou espera vê a frente que a última volta deixou.
- **A fronteira lia a constante.** O caso mandava o teto da pilha e um
  byte a mais: com a constante errada, mandaria 1481 bytes, recusados, e
  1480, aceitos e perdidos calados — a pilha não fragmenta. E o maior
  datagrama era lixo que o TFTP ignorava, sem prova de que tinha saído.
  Agora o teto do caso é o número, 1472, e o maior datagrama é um pedido
  de leitura que o TFTP responde.
- **O socket que sobrava na pilha só aparecia por acaso.** O `smoltcp`
  entrega o datagrama ao primeiro socket ligado à porta, na ordem do
  conjunto; o que sobrou de uma associação fechada só roubava o bloco da
  nova se viesse antes dela. E o que só se desliga, sem sair, solta a
  porta e não aparecia nunca. A suíte agora confere que nenhum socket da
  pilha é de ninguém. Medido sem essa conferência: fechar desligando e
  deixando sobrevive; fechar e derrubar deixando ligado foram reprovados,
  nesta rodada, pela porta reaproveitada — porque o socket que sobrou
  estava antes do novo, o que depende de quais posições estavam livres.
- **A fila de saída cheia e a origem no consumo** não eram alcançadas por
  caso nenhum. A fila cheia agora é: um destino do enlace que não responde
  ao ARP segura tudo nela. A origem também: o alheio que chegou atrás de
  um datagrama do destino fica na frente quando aquele sai.

### As mutações do TLS e do envio que espera

Vinte e quatro mutações contra o que o TLS, o `random.read` e o envio que
espera prometem — catorze contra os casos da suíte de quatro núcleos, no
x86 (onze no kernel e na política, três no TLS do programa), oito contra
os testes do pacote `tls` no hospedeiro e duas contra o `xtask`: **vinte e
quatro reprovadas**.

| Mutação | Reprovada por |
|---|---|
| sem entropia, o `random.read` responde assim mesmo | `aleatorio: sem entropia nenhum byte sai` — o pedido não falhou fechado |
| o tamanho fora de 1 a 256 ajustado à faixa, calado | `aleatorio: os bytes saem pelo gate e a auditoria fica sem eles` — um tamanho fora da faixa foi atendido |
| o observador com `random.read` | o mesmo caso — quem não tem a permissão recebeu bytes —, e `tls: sem random.read nada sai` |
| o envio malformado com `wait` suspende | `rede: uma espera de envio por conexao` — o anexo que não confere esperou, em vez de ser recusado na hora |
| o envio nunca espera | `rede: o envio que nao cabe espera espaco`, `rede: o envio acorda pelo espaco e nao pelo dado`, `rede: a entrega do envio depois da espera e decidida`, `rede: uma espera de envio por conexao` e `rede: o console espera o envio` — sem espaço, nenhum suspendeu |
| a espera não vê o espaço abrir | os três primeiros, `rede: o canal guarda o anexo do envio que espera` e `rede: o console espera o envio` — o console só retomaria no prazo |
| o waker do envio registrado como o da leitura | `rede: o envio acorda pelo espaco e nao pelo dado` — o par confirmou, e a espera não acordou. Os outros 450 casos passam com ela: com o eco, a resposta acorda a leitura junto, e o envio passa por acordado; o par mudo da porta 9 existe por isso |
| uma vaga de espera só para os dois sentidos | `rede: uma espera de envio por conexao` — a leitura não esperou junto com o envio |
| o canal reexecuta sem o anexo guardado | `rede: o canal guarda o anexo do envio que espera` |
| a resposta de volta ao teto de 4 KiB | `armazem: o programa guarda pelo gate` e `tls: tres sessoes ao mesmo tempo` |
| o anexo de volta ao teto de 4 KiB | `armazem: o programa guarda pelo gate` |
| o programa conecta antes de pedir a semente e o relógio | `tls: o programa cifrado conversa pelo gate` e `tls: sem random.read nada sai` — a conexão foi decidida antes de haver semente |
| a recusa do gate vira `TECHNICAL_ERROR` no programa | `tls: o programa cifrado conversa pelo gate`, `tls: sem random.read nada sai`, e os casos do `pausado` — a recusa saiu com o código errado |
| o relógio do programa fixo em 2020 | `tls: o programa cifrado conversa pelo gate` e os três casos do `pausado` — `TLS_NOT_YET_VALID` |
| a recusa do certificado sem alerta | `o_nome_errado_e_recusado` — o servidor não recebeu o alerta |
| a sessão que falhou não fica quebrada | `a_sessao_que_falhou_nao_volta` |
| o ECDSA aceita qualquer assinatura | `ecdsa_recusa_a_outra_mensagem_e_o_der_torto`; sem ele, `a_raiz_com_o_mesmo_nome_e_outra_chave_e_recusada` e `o_certificate_verify_de_outra_chave_e_recusado`, na conversa |
| o Ed25519 sem a verificação estrita | `ed25519_recusa_a_chave_de_ordem_pequena` |
| o X25519 aceita o ponto de ordem pequena | `x25519_recusa_o_ponto_de_ordem_pequena` |
| o P-256 aceita o ponto comprimido | `p256_recusa_o_comprimido_e_o_fora_da_curva` |
| o nome errado lido como raiz desconhecida | `o_nome_errado_e_recusado` — `TLS_UNTRUSTED` no lugar de `TLS_NAME_MISMATCH` |
| o vencido lido como raiz desconhecida | `o_vencido_e_o_que_ainda_nao_vale_sao_recusados` e `o_relogio_de_quem_conecta_decide_a_validade` |
| um atalho na verificação (`dangerous()`) | o `xtask invariantes` — "um atalho na verificação do TLS" |
| o kernel depende do pacote `tls` | o `xtask invariantes` — "o kernel depende do pacote `tls` — o TLS é do programa" |

Desenhá-las mostrou dois testes que faltavam:

- **A verificação estrita do Ed25519 não era exercitada por nada** — a
  bancada assina com ECDSA P-256, e a troca do `verify_strict` pelo
  `verify` comum passaria por todos os testes. Três testes novos a cobrem:
  a assinatura válida, a chave de ordem pequena que a verificação comum
  aceita, e o ECDSA com outra mensagem e o DER torto.
- **O console de uma pessoa não esperava envio em caso nenhum** — o
  processo e o canal do agente, sim. O caso novo, na primeira versão,
  deixava sobreviver a espera que não vê o espaço: o console retomava no
  prazo de cinco segundos, dentro da janela do caso, e com o espaço já
  aberto a saída era a mesma. Agora a espera é a de dez segundos, e o caso
  exige a retomada em oito.

### As mutações do canal TCP

Trinta e nove mutações contra o que o canal do agente por TCP promete —
a mesma taxa, a mesma janela de apertos e a mesma revogação das portas, a
chave confirmada, o prazo do aperto, a escuta e os fluxos do firewall, a
geração da vaga, a contrapressão e os tetos, o coletor, a auditoria de
cada recusa, a presença só de quem confirmou, o arrendamento que cai com
a conexão e o processo que age pela chave —, trinta e cinco contra os
casos `canal tcp` da suíte de quatro núcleos, no x86, três contra os
testes do firewall no hospedeiro e uma contra o `xtask invariantes`:
**trinta e oito reprovadas, e uma equivalente**.

| Mutação | Reprovada por |
|---|---|
| a taxa só das sessões de 0 a 4 | `canal tcp: a mesma autoridade e a mesma taxa` — pela rede, quatro pedidos seguidos passaram de uma rajada de dois |
| a janela de apertos só das portas | todos os casos `canal tcp` — nenhum aperto pela rede entrou |
| a revogação só das portas | `canal tcp: revogar derruba a conexao viva` |
| a chave vale sem confirmação | `canal tcp: o aperto pela rede`, `canal tcp: a identidade nao se forja` e `canal tcp: o prazo do aperto` — a conexão foi do agente antes de ele confirmar, e o aperto repetido apareceu conectado |
| sem o prazo do aperto | `canal tcp: o prazo do aperto` |
| a escuta deixa entrar qualquer quadro | `firewall::testes::a_escuta_so_recebe_o_syn` e `a_escuta_nao_casa_como_quadrupla` |
| a escuta deixa sair qualquer quadro | `firewall::testes::a_escuta_so_responde` e `a_escuta_nao_casa_como_quadrupla` |
| a escuta casa como uma conversa | `firewall::testes::a_escuta_nao_casa_como_quadrupla` |
| sem a escuta na fotografia do firewall | todos os casos `canal tcp` — o SYN não passa, e a ponte não chega a vaga nenhuma |
| sem os fluxos das vagas | todos os casos `canal tcp` — a conexão aceita não conversa |
| o bloqueio não derruba o canal | `canal tcp: a regra do firewall derruba a conexao` |
| o bloqueio ignora o dono da regra | o mesmo caso — a regra de outro agente derrubou a conexão |
| a geração da vaga lida como a de uma porta | `canal tcp: quatro agentes e a vaga de cada um` — a conexão de rede do agente não era da conexão dele |
| o fim de uma conexão leva a sessão da seguinte | `canal tcp: o aperto pela rede` |
| sem a contrapressão da saída | `canal tcp: quem nao le espera` — com a saída no limiar, a sessão continuou lendo |
| a saída sem teto | `canal tcp: a saida tem teto` — oito respostas grandes de um quadro só passaram de 256 KiB |
| a entrada sem teto | `canal tcp: a entrada cheia espera no socket` |
| o coletor não trata as pendências | todos os casos `canal tcp` — as vagas não voltaram a escutar |
| o fim da sessão não fecha a conexão | `canal tcp: a identidade nao se forja`, `canal tcp: revogar derruba a conexao viva` e `canal tcp: o nsf observa sem ser autoridade` |
| a recusa antes do aperto não é gravada | `canal tcp: a identidade nao se forja` — o pedido em claro |
| o transporte com o nome da porta | `canal tcp: o aperto pela rede` e `canal tcp: quatro agentes e a vaga de cada um` |
| o prazo não esquece a sessão não confirmada | `canal tcp: o prazo do aperto` |
| o fim da conexão não esquece a sessão | dez casos — a sessão ficou, e a vaga não voltou a ser livre |
| o aperto diz outra sessão | `canal tcp: o aperto pela rede` |
| a porta do `xtask` não é a do kernel | o `xtask invariantes` |
| o fluxo da vaga sem o agente | `canal tcp: a regra do firewall derruba a conexao` — a regra do agente não alcançou a conexão dele |
| os conectados só das portas | `canal tcp: o aperto pela rede` e `canal tcp: quatro agentes e a vaga de cada um` |
| os conectados contam o aperto não confirmado | `canal tcp: o aperto pela rede`, `canal tcp: a identidade nao se forja` e `canal tcp: o prazo do aperto` |
| o aperto do TCP gravado na resposta, e não na confirmação | `canal tcp: o aperto pela rede` e `canal tcp: a identidade nao se forja` |
| o fim não confirmado não é gravado | `canal tcp: a identidade nao se forja` e `canal tcp: o prazo do aperto` |
| `agent.sessions` mostra o aperto não confirmado como de um agente | `canal tcp: a identidade nao se forja` |
| a sessão não confirmada sem o par | os mesmos dois — a recusa sem o par |
| a queda antes da confirmação não é gravada | `canal tcp: a identidade nao se forja` — quem repete e sai |
| a confirmação não marca a sessão | quatro casos — o agente que confirmou não aparece |
| o fim da sessão TCP não solta os arrendamentos | `canal tcp: o conflito e o fim da conexao` — e só ele: sem o caso, a mesma mutação passa pelos casos `coordenacao` e pelos outros treze `canal tcp` |
| o comando da sessão TCP sem a chave | `canal tcp: o programa lancado pela rede` e `canal tcp: o processo sem a conexao e a revogacao` — o operador nem lança o programa |
| a autoridade do processo presa à conexão viva | `canal tcp: o processo sem a conexao e a revogacao`, e só ele — caída a conexão, o processo perdeu o agente |
| a revogação não alcança o processo lançado pela rede | o mesmo caso, e só ele — o processo seguiu com o papel da chave revogada |
| a pendência sai da lista antes de tratada | equivalente — ver abaixo |

Desenhá-las mostrou quatro lugares que nenhum caso alcançava — cada um
ganhou o seu antes da rodada final:

- **O teto da entrada.** Nenhum caso mandava mais do que a entrada da
  vaga guarda, e tirar o teto passaria. O caso `canal tcp: a entrada
  cheia espera no socket` manda 46 KiB de pedidos legítimos com a tarefa
  parada: a entrada para nos 16 KiB, o resto espera no socket, e andando a
  tarefa os 24 pedidos são atendidos na ordem.
- **O teto da saída sobreviveu à primeira rodada**, e mostrou por que
  importa: a contrapressão espera depois de cada linha que fecha, mas as
  linhas de um mesmo quadro decifrado são atendidas uma atrás da outra,
  sem a espera entre elas. Um quadro com oito `audit.tail` grandes leva a
  saída da vaga muito além do limiar — e só o teto a segura. O caso
  `canal tcp: a saida tem teto` faz isso com a saída da pilha segura: a
  resposta que não cabe não sai, a sessão acaba e a perda é contada, e a
  saída nunca passa de 256 KiB.
- **O `agent.sessions` do aperto não confirmado** e **a queda antes da
  confirmação** não eram olhados: o caso da identidade passou a conferir
  que o aperto repetido aparece como não autenticado, sem nome de agente,
  e que quem repete e sai deixa uma recusa gravada com a chave alegada.

E, depois da primeira rodada, mais dois — cada um com o seu caso, e as
mutações que só ele reprova:

- **O arrendamento de quem cai da rede.** O fim de uma sessão TCP solta
  os arrendamentos dela pelo mesmo caminho das portas, mas nenhum caso
  tomava um arrendamento pela rede: a mutação que deixa de soltar os das
  vagas sobreviveu aos casos `coordenacao`, que usam as portas, e aos
  outros treze `canal tcp`. O caso `canal tcp: o conflito e o fim da
  conexao` põe dois agentes pela rede na linha de comando — a versão velha
  e o arrendamento de outro são `CONFLICT`, gravados com a sessão TCP de
  quem pediu, e nada muda —, derruba a conexão de quem tinha o
  arrendamento e espera a soltura gravada em nome dele; a mesma chave,
  conectada de novo, não herda nada.
- **O processo lançado pela rede, sem a conexão.** O caso `canal tcp: o
  programa lancado pela rede` confere as recusas de dentro do processo,
  mas não o que acontece com ele depois da conexão. O caso `canal tcp: o
  processo sem a conexao e a revogacao` lança o `isolavel` pela rede: ele
  continua o agente depois que a conexão cai — a autoridade é da chave —,
  e a perde na hora em que a chave é revogada. As duas mutações — a
  autoridade do processo presa à conexão viva, e a revogação que não o
  alcança — passam pelo caso antigo e são reprovadas pelo novo; o caso
  `politica: o processo age como o agente` olha só as portas.

A equivalente: a pendência que sai da lista antes de ser tratada. Nada no
kernel lê o tamanho da lista — só a suíte, para saber se a vaga ficou
livre —, e a ordem só muda o que ela observa: a corrida que a mudança
fechou apareceu uma vez, no caso do prazo, que conferia a recusa logo
depois de a lista esvaziar, antes de o coletor gravá-la.

### As mutações do HTTP

Trinta e três mutações contra o que o HTTP de um programa promete — o gate
em cada pedido, a autoridade de quem lançou o processo e só ela, a
revogação, a contenção e o fim da sessão no meio da conversa, o firewall
com o código dele, o DNS e o certificado que não autorizam, as falhas que
não se misturam, o protocolo estreito e os limites — e contra o que o
exercício corrigiu: o número da conexão cortada e a leitura da captura do
NSF. Vinte e cinco contra os casos `http:` e `dns:` da suíte de quatro
núcleos, no x86, seis contra os testes do hospedeiro e duas contra o
`xtask invariantes` — três delas também contra o outro lado:
**trinta e três reprovadas**.

| Mutação | Reprovada por |
|---|---|
| o `net.recv` sem decisão do gate | `http: a revogacao no meio do pedido` — revogado o papel do agente, a resposta lenta chegou: `200`, e não `DENY_ROLE` |
| o destino decide sozinho: o papel de quem pede não conta na rede | `http: a conexao mantida e decidida a cada pedido` — com o servidor fora do alcance do operador, o pedido seguinte deu `200 4`, e não `DENY_RESOURCE` |
| o certificado autoriza: a sessão cifrada esconde a recusa de baixo | `http: a contencao no meio do pedido` — o processo contido ouviu `HTTP_CLOSED`, e não `DENY_CONTAINED` |
| um comando `http.*` no registro | o `xtask invariantes` — um comando do HTTP fora do ponto de decisão |
| a identidade do agente perdida no processo | `http: a revogacao no meio do pedido` e `http: varias visitas ao mesmo tempo` — a conexão do processo não foi decidida com o agente que o lançou |
| o processo (o PID) como identidade depois do fim da sessão | `http: o fim da sessao no meio do pedido` — depois do `logout`, a resposta lenta chegou: `200`, e não `DENY_NOT_AUTHENTICATED` |
| a conexão sobrevive à revogação: o papel guardado | `http: a revogacao no meio do pedido` — `200`, e não `DENY_ROLE` |
| o corte do firewall tira o número: a conexão some | `http: o firewall corta a conexao com o codigo dele` — `DENY_RESOURCE`, e não `FIREWALL_BLOCKED`: o defeito que o exercício achou |
| o firewall ignorado na conexão nova | o mesmo caso — a conexão saiu sem o código do firewall, e esperou até `NETWORK_TIMEOUT` |
| a recusa do gate vira erro do TLS | `http: a contencao no meio do pedido` — `TLS_INTERRUPTED`, e não `DENY_CONTAINED` |
| o nome decide o destino, e não o endereço que o DNS deu | `http: o nome pelo dns e o destino pelo gate` — o nome religado para fora do alcance conversou: `200`, e não `DENY_RESOURCE` |
| o processo com outra autoridade que não a de quem o lançou | `http: a pagina pelo gate` — as conexões da página não foram decididas em nome da pessoa |
| o enquadramento ambíguo aceito: o erro de protocolo vira resposta | `testes::o_enquadramento_ambiguo_e_recusado`, no hospedeiro; de ponta a ponta, `http: a pagina pelo gate` |
| a recusa do gate vira falha técnica no transporte | `http: a revogacao no meio do pedido` — `local TECHNICAL_ERROR`, e não `denied DENY_ROLE` |
| o `DENY_` na família genérica | `categoria::testes::cada_codigo_na_sua_familia`; de ponta a ponta, `http: a revogacao no meio do pedido` — `local DENY_ROLE` |
| a contenção ignorada pelo gate | `http: a contencao no meio do pedido` — o processo contido não ouviu `DENY_CONTAINED` |
| o corte do firewall sem registro na auditoria | `http: o firewall corta a conexao com o codigo dele` — o corte não foi gravado |
| o NSF barra direto, fora do gate | o `xtask invariantes` — uma operação protegida chamada fora do ponto de decisão |
| a conexão derrubada lida como fim em ordem | `http: a conexao mantida e decidida a cada pedido` — `HTTP_CLOSED`, e não `CONNECTION_RESET` |
| o firewall na família do transporte | `categoria::testes::cada_codigo_na_sua_familia` |
| o que chega sem pedido vira a resposta seguinte | `testes::o_que_chega_sem_pedido_nao_vira_a_resposta_seguinte` e `o_que_nao_deixa_a_conexao_para_o_pedido_seguinte` |
| o corpo anunciado sem limite | `testes::o_tamanho_anunciado_grande_demais_nao_espera_o_corpo` e `os_limites_param_a_leitura` |
| o fecho da cortada não solta o número | `http: o firewall corta a conexao com o codigo dele` — o número cortado ficou com o programa depois de ele o largar |
| o coletor não esquece as cortadas de quem acabou | `http: o processo que acaba solta as conexoes` |
| o DNS esconde a recusa do gate | `http: a revogacao no meio do pedido` — `dns DNS_UNAVAILABLE`, e não `denied DENY_ROLE` |
| a conexão não leva o pedido seguinte | `testes::a_conexao_leva_o_pedido_seguinte_quando_a_resposta_deixa` |
| o prazo vira fim em ordem | `http: a conexao mantida e decidida a cada pedido` — o servidor mudo deu `HTTP_CLOSED`, e não `NETWORK_TIMEOUT` |
| a leitura cortada sem a regra nem o registro | `http: o firewall corta a conexao com o codigo dele` — o corte não foi gravado |
| a tabela não acha a cortada | o mesmo caso — `INVALID_REQUEST`, e não `FIREWALL_BLOCKED` |
| o gate não acha o destino da cortada | o mesmo caso — `DENY_RESOURCE`, e não `FIREWALL_BLOCKED` |
| o NSF recomeçado lê a captura de antes dele | `dns: o NSF le a rajada inteira` — leu mais do que a rajada; no hospedeiro, `o_agora_vale_tambem_para_a_captura` |
| o NSF lê um lote só por volta | `dns: o NSF le a rajada inteira` — parou nos primeiros 16 datagramas |
| a observação recusada insiste na mesma volta | o mesmo caso — três recusas numa volta |

A autorização só pelo destino teve de ser escrita duas vezes. A primeira
trocava o papel de quem pede pelo do sistema em `decidir_destino` — e
sobreviveu, com o caso da revogação e com o da conexão mantida: aquela
função decide o **destinatário de uma mensagem**, e não o destino de uma
conexão, que passa pela conta comum do gate, `decidir`, como qualquer
recurso. A mutação que vale troca o papel ali, só para os destinos
`tcp:`; o caso da conexão mantida, que tira o servidor do alcance do
operador e o deixa no do sistema, a reprova.

### As mutações da janela

Catorze mutações contra o que a janela do TCP promete — a rajada da placa,
o teto do pedido, a memória das conexões e das associações, o pico do heap
e o registro do TLS que cabe num envio —, contra os casos `rede:`, `heap:`
e `tls:` da suíte de quatro núcleos, no x86: **doze reprovadas**, e duas
equivalentes.

| Mutação | Reprovada por |
|---|---|
| a rajada da placa de volta a um quadro | `rede: a janela e o buffer inteiro, e fecha quando ninguem le` — a janela anunciada não é o buffer |
| quatro buffers de recepção | a compilação: a rajada da placa não cobre a janela de uma conexão |
| quatro buffers de recepção, sem a asserção | `rede: a janela e o buffer inteiro, e fecha quando ninguem le` |
| o envio maior que o buffer aceito em parte | `rede: o pedido maior que o buffer` — não foi recusado inteiro |
| o envio do buffer exato recusado | o mesmo caso — o buffer exato não coube |
| a leitura sem os dois tetos | o kernel cai na leitura com `max` enorme: um bloco do tamanho do pedido |
| a conexão guarda um buffer a mais | `rede: a memoria das conexoes volta` — mais que os dois buffers |
| o fecho terminado não sai do conjunto de sockets | o mesmo caso — fechadas as conexões, o heap não voltou |
| a associação UDP com o buffer do TCP | o mesmo caso — as associações tomam mais que o espaço dos datagramas |
| o pico do heap não acompanha | `heap: o pico e o pior momento` |
| o pico do heap é o alocado de agora | o mesmo caso — o pico desceu quando a alocação saiu |
| o registro do TLS maior que o envio | a compilação dos programas: o registro não cabe num envio |

As duas equivalentes são os dois tetos da leitura, cada um sozinho: a pilha
corta o que lê no buffer, e o comando corta o `max` antes de pedir. São de
propósito — um em quem guarda o recurso, outro em quem fala com o pedido —,
e tirar os dois junto derruba o kernel, a mutação da tabela. Duas
sobreviveram à primeira rodada, e os casos mudaram por elas: o buffer do
UDP — o caso da memória passou a medir as associações também —, e o pico
que segue o alocado de agora — o caso do pico passou a alocar depois de a
alocação grande sair, e a conferir que ele não desceu.

### As mutações do plano de dados

Vinte e uma mutações contra o que o plano de dados promete — o gate
inteiro em cada pedido, a auditoria de cada um, a revogação, a contenção e
o firewall no pedido seguinte, a decisão de novo depois da espera, a posse
e a existência do recurso, a contrapressão, nenhum registro perdido e
nenhuma monopolização calada —, vinte contra os casos `dados:` da suíte de
quatro núcleos, no x86, e uma contra as invariantes do `xtask`: **dezenove
reprovadas**, e duas equivalentes.

| Mutação | Reprovada por |
|---|---|
| a política não decide o pedido de dados: o gate pulado | `dados: a revogacao no meio da transferencia` — o pedido depois da revogação passou —, e outros dois casos |
| o handler chamado fora da licença do gate | `cargo xtask invariantes`: um comando executa só por `autorizar` e `Autorizado::executar` |
| os dados sem auditoria | `dados: a transferencia grande com a politica padrao` — o journal não tem cada decisão do `vazao` —, e outros sete |
| o papel revogado não recusa os dados | `dados: a revogacao no meio da transferencia` |
| a contenção fora do orçamento: o contido com o orçamento do fecho | `dados: o contido nao tem o orcamento do fecho` |
| a conexão cortada pelo firewall continua plano de dados | `dados: o firewall no meio da transferencia` — a cortada foi tratada como recurso aberto |
| a reexecução depois da espera sem a política | `dados: a reautorizacao depois da espera` — o adiado mandou bytes depois do firewall, da revogação ou do isolamento que vieram no meio |
| a conexão de outro titular, no gate: o destino resolvido sem o dono | `dados: a conexao de outro titular` — outro titular usou a conexão da dona |
| qualquer número é uma conexão aberta, no orçamento | `dados: o firewall no meio da transferencia` — a cortada virou recurso aberto |
| o número que não resolve vira um destino, no gate | `dados: a conexao que nao existe`, `dados: a conexao de outro titular` e `dados: a contencao no meio da transferencia` |
| sem contrapressão: sempre há lugar | `dados: a inundacao de um byte` — a inundação com `wait` não foi contida —, e outros cinco |
| o pedido adiado largado pelo despachante dos processos | `dados: a inundacao de um byte` — um envio foi recusado em vez de esperar —, e outros cinco |
| o journal fora do caminho: o anel transborda | `dados: a auditoria inteira sob inundacao` — com o journal parado, a inundação não esperou |
| sem partilha: só o teto | `dados: a inundacao de um byte` e `dados: a partilha entre principais` — um principal sozinho passou da parte dele |
| a parte do maior principal some das medidas | `dados: as medidas do orcamento` e `dados: a partilha entre principais` — a partilha não aparece nas medidas |
| o fecho volta à taxa | `dados: varias conexoes do mesmo programa` — os fechos não foram decididos como fecho —, e outros quatro |
| o pedido recusado fica fora da taxa | `dados: a revogacao no meio da transferencia` — o revogado teve o benefício do plano de dados |
| o pedido de dados sem `wait`, com o caminho cheio, passa de graça | `dados: a inundacao de um byte` — sem `wait`, a inundação não voltou à taxa |
| sem margem: o teto é o fim do anel | `dados: as medidas do orcamento` — o envio passou com o caminho cheio —, e outros três |

As duas equivalentes são a outra metade de duas camadas, cada uma
suficiente sozinha:

- **a contenção fora do gate, só para os dados.** O pedido de quem está
  contido nunca chega ao orçamento dos dados — a estimativa o põe na taxa
  antes de tudo —, e a contenção do gate o recusa; tirar a contenção do
  gate só para o orçamento dos dados é tirá-la de um estado que não
  acontece;
- **a conexão de outro titular, no orçamento.** A estimativa dá ao pedido o
  orçamento dos dados, o gate o recusa (`DENY_RESOURCE`), e a recusa volta
  à taxa depois da decisão: o mesmo desfecho, com a mesma ficha gasta.

Já a mutação do número que não resolve, no orçamento — escrita para a
conexão inexistente —, morreu pelo firewall: sem a conferência, a conexão
cortada também virava recurso aberto.

**A primeira rodada achou um caso que dependia da pressa da bancada.** O
`dados: o fecho com a taxa esgotada` esgotava a ficha abrindo conexões, e
cada abertura vai ao eco da bancada e volta: com outra máquina na bancada
— a das mutações —, a abertura levava mais de 20 ms, a ficha voltava antes
da seguinte, e a taxa de 50 por segundo não se esgotava nunca. Reprovava
qualquer mutação, e a suíte inteira sob carga. O caso agora esgota a ficha
pelo relógio, um pedido que não sai da máquina, e confere à parte que a
abertura sem ficha é recusada pela taxa; as mutações que ele tinha
reprovado sozinho rodaram de novo.

**A matriz achou um caso de antes, pelo mesmo coletor do sono acordado
por NMI.** Na suíte com a virtio-gpu, no x86, o caso `mmio: mapeamento
que falha no meio desfaz tudo` reprovou: os frames livres subiram 756
durante um mapeamento que não devolve nada. A janela do caso mascara as
interrupções, o que segura o coletor neste núcleo, e não nos outros: o de
outro núcleo desmontava, um a um, por mais de um segundo, os 90 fios que
o caso do zumbi deixou, e o fim da leva caiu dentro da janela. O caso
agora recolhe os mortos antes e espera a leva de outro núcleo acabar — a
conta dos recolhidos parada —, como o caso do custo do coletor já fazia;
a suíte com a virtio-gpu passou inteira em seguida.

### As mutações da compressão

Quarenta e três mutações contra o que a compressão promete — o teto antes
de descomprimir, cada soma e cada regra do formato, a negociação, o
cliente que não adivinha, e o gate que não sabe de nada disso —: trinta e
nove contra os testes do pacote `http`, duas de ponta a ponta contra a
suíte do x86, e duas contra as invariantes do `xtask`. **Todas
reprovadas** — uma delas só depois de um teste novo, abaixo.

| Mutação | Reprovada por |
|---|---|
| sem o teto da saída | `a_bomba_para_no_teto`, `o_teto_do_corpo_decodificado` e outros dois |
| o teto com um a menos | `o_teto_do_corpo_decodificado` — o corpo do tamanho exato do teto não passou |
| a reserva que dobra sem olhar o teto | `a_bomba_para_no_teto` e `decodifica_em_paralelo` — o pico do monte passou de uma vez e meia o teto |
| sem o teto de quem pede, na troca | `o_teto_do_corpo_decodificado_na_troca` |
| o gzip sem o CRC-32; sem o tamanho; sem o CRC da cabeça | `o_involucro_do_gzip`, e o CRC também por `nenhum_bit_trocado_vira_outro_conteudo`; o tamanho por `o_tamanho_anunciado_nao_reserva_nada` |
| o gzip que aceita bytes depois do último membro; sem os bits reservados; o rodapé cortado lido como zeros | `o_involucro_do_gzip`, e o rodapé por `o_fluxo_cortado_em_qualquer_ponto` |
| o zlib sem o Adler-32; com o dicionário preestabelecido; sem o `FCHECK`; com a janela maior que 32 KiB | `o_involucro_do_zlib`, e o dicionário por `o_dicionario_preestabelecido_e_recusado` |
| o polinômio do CRC-32 trocado; o pedaço do Adler-32 grande demais | `as_somas_publicadas` — as somas que a literatura publica —, e outros seis |
| a codificação desconhecida lida como `identity`; o `x-gzip` desconhecido | `a_negociacao`, e `o_corpo_comprimido_chega_decodificado` |
| duas codificações empilhadas aceitas | `a_negociacao` e `a_codificacao_que_o_pedido_nao_aceitou_nao_le_o_corpo` |
| o cliente decodifica o que o pedido não aceitou | `a_negociacao`; e, de ponta a ponta, `compressao: o corpo comprimido pelo gate` — o programa recebeu um gzip que não pediu como se fosse o conteúdo |
| o pedido sem o `Accept-Encoding`; o `identity` de quem não aceita nada trocado; o `Accept-Encoding` de quem chama | os testes do pedido — `o_accept_encoding_diz_o_que_o_cliente_decodifica` e `os_cabecalhos_de_quem_chama_sao_conferidos` |
| o corpo vazio decodificado; a codificação conferida sem corpo | `sem_corpo_a_codificacao_nao_importa` |
| a conexão fica depois do conteúdo que não se decodifica | `o_conteudo_que_nao_se_decodifica_nao_vira_resposta` e outros três |
| o fim da entrada lido como zeros; o código que acaba no meio aceito | `o_fluxo_cortado_em_qualquer_ponto`, e o código também por `nenhum_bit_trocado_vira_outro_conteudo` |
| a distância antes do começo do membro; dois membros na mesma janela | `cada_membro_e_um_fluxo` |
| o código de Huffman incompleto; o de comprimentos incompleto; sem o fim de bloco; literais ou distâncias demais; os símbolos 286 e 287; sem `LEN` e `NLEN`; o bloco de tipo 3; a repetição sem anterior | `o_que_a_rfc_proibe_e_recusado` |
| a repetição que passa do total, cortada no total | `o_que_a_rfc_proibe_e_recusado` — depois do caso novo |
| sem o teto, de ponta a ponta | `compressao: o corpo comprimido pelo gate` — a bomba fez o processo pedir 16 MiB de monte, e ele caiu no pânico da alocação; o kernel e a suíte seguiram |
| o kernel fala de `gzip`; a política fala de `deflate` | `cargo xtask invariantes`: a compressão do HTTP no kernel ou na política |

**A sobrevivente que pediu um teste.** A repetição que passa do total de
comprimentos, cortada no total em vez de recusada, passou na primeira
rodada: o caso de "repetição demais" que existia, ao passar do total,
também deixava o código sem o fim de bloco — e era essa outra regra que o
recusava. O caso novo passa do total e só isso: cortado, o resto seria um
código válido, o fim de bloco sozinho.

**O teste que faltava antes de qualquer mutação.** Nenhum teste dizia que
o segundo membro de um gzip não pode copiar do primeiro: cada membro é um
fluxo DEFLATE, com a janela dele. O decodificador já fazia certo — a
distância é contada do começo do membro —, e o caso
`cada_membro_e_um_fluxo` entrou antes da bateria, que confirmou que ele
mata as duas mutações.

### As mutações dos cookies

Setenta e seis mutações contra o que os cookies prometem — cada regra do
pote, o relógio, os tetos, a troca, e a autoridade que um cookie não muda
—: sessenta e oito contra os testes do pacote `http`, seis de ponta a ponta
contra a suíte do x86, e duas contra as invariantes do `xtask`. **Todas
reprovadas** — quatro só depois de um caso novo, abaixo. Outras duas, de
ponta a ponta, são equivalentes, e o porquê vem depois da tabela.

| Mutação | Reprovada por |
|---|---|
| o domínio sem a fronteira do ponto; o `Domain` de outro host; o de um rótulo só aceito | `o_dominio` |
| o host só do host casando por sufixo; o `Domain` com caixa; com o ponto do começo | `o_dominio` e `o_set_cookie_se_le` |
| o host por endereço com `Domain`; o endereço que casa por sufixo | `o_host_por_endereco_so_tem_cookie_dele` — o sufixo, depois do caso novo |
| o caminho sem a fronteira; o caminho padrão que é o do pedido; o `Path` sem barra aceito | `o_caminho` e `o_set_cookie_se_le` |
| o `Secure` de origem clara; o `Secure` que vai por `http`; a origem clara que sobrescreve o seguro | `o_secure` |
| o `HttpOnly` visível ao programa; criado pela API; sobrescrito pela API; a API como se fosse a rede; os visíveis com o `HttpOnly` | `o_httponly_nao_sai_do_pote_para_o_programa` |
| o `Strict` que vai de outro site; o `Lax` em qualquer pedido de outro site; num `POST` de navegação; o `None` sem `Secure`; o outro site que põe `Strict` ou `Lax`; o padrão `None` | `o_samesite` |
| o contexto do pedido ignorado no envio; na resposta | `o_contexto_do_pedido_vai_ao_pote`; a resposta, por `o_contexto_do_pedido_vale_para_a_resposta`, novo |
| o `__Secure-` sem `Secure`; o `__Host-` com `Domain`; com outro caminho; o prefixo com caixa | `os_prefixos`, e o `nada_do_que_o_servidor_manda_quebra_o_pote` |
| o `Max-Age=0` que não apaga; o `Expires` que vence o `Max-Age`; sem o teto de 400 dias, num e no outro; o vencido que vai; o vencido no segundo exato | `a_validade`, `o_que_ja_venceu_apaga` e `sem_relogio_a_validade_nao_se_confere` |
| a data com o ano de dois dígitos no século errado; a que não existe; o bissexto de quatro em quatro; antes de 1601; a hora fora de faixa; o `Max-Age` com lixo | `as_datas_de_cookie`, e o lixo por `a_validade` e pelo `nada_do_que_o_servidor_manda_quebra_o_pote` |
| sem relógio, a validade vai; os retidos não contados; os retidos que não chegam a quem chama | `sem_relogio_a_validade_nao_se_confere`; os retidos, por `sem_relogio_a_troca_diz_quantos_ficaram`, que entrou com eles |
| o relógio sempre lido; lido a cada vez; lido duas vezes na troca | `o_relogio_so_e_lido_quando_um_cookie_tem_validade`; a troca, por `a_troca_le_o_relogio_uma_vez`, novo |
| sem o teto por domínio; sem o de bytes; sem o do pote; o despejo do mais novo, no domínio e no pote; o uso que não conta | `os_limites_e_o_despejo` — o uso, depois do caso novo —, e os bytes também por `o_monte_do_pote_tem_teto` |
| o cookie grande aceito; o atributo grande lido; o nome vazio; o controle no valor; o par sem `=` como um nome sem valor | `o_que_nao_e_cookie_e_recusado` e `o_set_cookie_se_le` |
| a ordem do cabeçalho invertida; o desempate pelo mais novo; o substituto que perde a criação | `a_ordem_do_cabecalho` |
| qualquer cabeçalho lido como cookie; o `Set-Cookie` que fica na resposta; o pote que não vai no pedido | `a_troca_com_o_pote` |
| o `Cookie` de quem chama | `os_cabecalhos_de_quem_chama_sao_conferidos` e `sem_pote_nada_de_cookie` |
| o `Debug` do pote que mostra o valor | `o_debug_do_pote_nao_mostra_valor`, que entrou com a correção — antes dela, um `{:?}` do pote mostrava a sessão |
| a revogação ignorada no plano de dados; o revogado que fica com o papel | `cookies: a revogacao nao passa pelo cookie` — com a sessão no pote, o pedido depois da revogação deu `200 privado`, e não `DENY_ROLE` |
| a contenção que não alcança a rede | `cookies: a contencao nao passa pelo cookie` — o contido ouviu `DENY_RESOURCE`, e não a contenção |
| o firewall sem as duas camadas da conexão aberta: o bloqueio que não a derruba, e o envio que não confere a regra | `cookies: o firewall nao passa pelo cookie` — nada passou, porque a placa ainda descarta os quadros do fluxo barrado, mas o programa ouviu `NETWORK_TIMEOUT`, e não `FIREWALL_BLOCKED` |
| o processo de um agente decidido em nome de uma pessoa | `cookies: pessoa e agente cada um com o seu` e `cookies: varios ao mesmo tempo` |
| um pote só no processo, o que o programa passa ignorado | `cookies: o programa inteiro pelo gate` — a sessão de um pote foi pelo outro —, e os outros sete casos |
| o kernel fala de cookie; a política também | `cargo xtask invariantes`: um cookie no kernel ou na política |

**As que pediram um caso.** O endereço que casa por sufixo passou na
primeira rodada: nenhum caso tinha um cookie de domínio que terminasse
como um endereço. O caso novo põe `Domain=0.2.100` a partir de
`x.0.2.100` — um nome —, e confere que ele vai a `y.0.2.100` e não a
`10.0.2.100`. O uso que não conta também passou: o caso do despejo
renovava o cookie mais velho substituindo-o, e a substituição já o
deixava novo; o caso agora o renova só usando. E duas da troca com o
pote: o contexto do pedido ignorado na resposta, e o relógio lido duas
vezes numa troca — `o_contexto_do_pedido_vale_para_a_resposta` e
`a_troca_le_o_relogio_uma_vez` entraram para elas. Uma terceira era
equivalente — ler o par sem `=` como um nome vazio, que o nome vazio
recusa do mesmo jeito — e foi trocada pela que o lê como um nome sem
valor.

**As equivalentes.** A contenção ignorada só no plano de dados, e o
bloqueio que só não derruba a conexão, não mudam nada aqui: a contenção
derruba as conexões do contido, e o pedido seguinte, sem conexão, é
decidido no caminho de controle, onde a contenção recusa; e o envio
confere a regra do firewall a cada vez, com a conexão viva ou não. São
camadas que se cobrem, e as duas mutações que os cookies reprovam tiram
as duas de cada vez.

### As mutações do HTTP/2

Setenta e oito mutações contra o que o HTTP/2 promete — as correntes e o
teto delas, as janelas, o erro que é da corrente e o que é da conexão, o
HPACK, os quadros, o ALPN e o h2c, e a autoridade que uma corrente não
muda —: setenta contra os testes do pacote `http`, os do hospedeiro e os
contra o `nghttpd`; seis de ponta a ponta contra a suíte do x86; e duas
contra as invariantes do `xtask`. **Setenta e seis reprovadas** — duas só
depois de um caso novo, abaixo. As outras duas são equivalentes, e o
porquê vem depois da tabela.

| Mutação | Reprovada por |
|---|---|
| sem o teto das correntes guardadas; sem o máximo de correntes do servidor; o máximo dele ignorado | `as_correntes_de_quem_chama_tem_teto` e `o_servidor_pode_aceitar_menos_correntes` |
| a janela da corrente esperada que não abre; a janela inicial nova que não vale para as abertas | `a_corrente_parada_segura_so_a_janela_dela`, `a_janela_da_corrente_esperada_abre_de_uma_vez` e `o_corpo_do_pedido_espera_a_janela_do_servidor` |
| a janela da conexão que não reabre | `a_janela_da_conexao_se_reabre`, novo |
| os dados além da janela da corrente; a janela da corrente que transborda; a da conexão | `os_dados_alem_da_janela_da_corrente`, `a_janela_do_pedido_alem_do_maximo_e_da_corrente` e `os_erros_da_conexao` |
| o corpo sem limite | `os_limites_da_resposta_sao_da_corrente`, depois do caso novo |
| os dados antes da cabeça; o corpo além e aquém do `content-length` | `o_corpo_que_nao_confere_com_a_cabeca` |
| a cabeça numa corrente ociosa; o reinício de uma ociosa; o *push* ligado aceito; o maior quadro fora da faixa; o quadro maior que o anunciado | `os_erros_da_conexao` |
| as `CONTINUATION` sem fim; o bloco cru sem teto; a enxurrada sem teto; o `PING` contado como progresso | `as_enxurradas` |
| a cabeça depois do fim da corrente | `depois_do_fim_da_corrente_nada_dela` |
| a lista além do limite que passa | `a_cabeca_alem_do_limite_mantem_a_tabela_certa` e `os_limites_da_resposta_sao_da_corrente` |
| o `101` aceito; o nome em maiúsculas; o cabeçalho da conexão; o pseudo-cabeçalho depois dos outros; o valor com espaço nas pontas; o status fora da faixa | `as_respostas_malformadas_sao_so_da_corrente` |
| a informativa que acaba a corrente; as informativas sem fim | `as_informativas_passam_e_nao_acabam_a_corrente` |
| os *trailers* sem o fim | `os_trailers_tortos` |
| a recusa do servidor que vira reinício | `a_recusa_do_servidor_no_meio_do_corpo_do_pedido` e `o_reinicio_do_servidor` |
| os ajustes sem `ACK`; o primeiro bloco sem a tabela deste lado em zero | `uma_troca` |
| o `GOAWAY` que não recusa as correntes de depois; o código dele esquecido no fecho | `o_adeus_do_servidor` |
| o erro da corrente sem `RST_STREAM`; o `RST_STREAM` numa corrente já fechada; o erro da conexão sem `GOAWAY`; os reconhecimentos que esperam o pedido seguinte | os casos de cada recusa, que conferem o que sai pelo fio: `as_respostas_malformadas_sao_so_da_corrente`, `os_erros_da_conexao`, `o_prefacio_que_nao_e_do_http2`, `mil_pings_com_progresso_no_meio_passam` e outros |
| a falha da conexão que não chega às outras correntes | os testes do pacote não terminam: a corrente que esperava espera para sempre |
| a corrente de outra conexão | `a_corrente_de_outra_conexao_nao_e_entregue` |
| o `cookie` indexável; a credencial indexável | `os_cookies_pelo_pote_e_o_cookie_nunca_indexado` e `o_https_a_porta_e_os_cabecalhos_de_quem_chama` |
| o `POST` sem corpo sem `content-length` | `o_post_sem_corpo_diz_zero_e_acaba_na_cabeca` |
| sem o prefácio do servidor | `o_prefacio_que_nao_e_do_http2` |
| cancelar sem `RST_STREAM`; o limite que sai como `PROTOCOL_ERROR` no `RST_STREAM` | `cancelar_larga_a_corrente` e `os_limites_da_resposta_sao_da_corrente` |
| o HPACK: o tamanho da tabela mudado depois de um campo, ou acima do anunciado; a lista sem limite; o literal indexado que não entra na tabela; a entrada sem os 32 bytes; o inteiro sem teto | `a_tabela_muda_de_tamanho_so_no_comeco_e_ate_o_anunciado`, `a_lista_para_no_teto_e_a_tabela_continua_certa`, `a_tabela_dinamica_do_servidor_atravessa_as_correntes`, `baixar_a_tabela_tira_os_mais_velhos`, `um_inteiro_sem_fim_ou_grande_demais` e os vetores da RFC |
| o Huffman: o EOS numa cadeia; o preenchimento longo, ou que não é de uns; a cadeia sem teto | `o_eos_nao_pode_estar_na_cadeia`, `uma_cadeia_que_nao_e_huffman`, `o_preenchimento_e_o_comeco_do_eos_com_menos_de_oito_bits` e `a_cadeia_decodificada_nao_passa_do_teto` |
| os quadros: `DATA` na corrente zero; o preenchimento maior que a carga; a cabeça que depende de si mesma; o `SETTINGS` fora de seis em seis, com carga no `ACK` ou numa corrente; o `WINDOW_UPDATE` de zero; o `GOAWAY` numa corrente | `os_dados_com_e_sem_preenchimento`, `os_cabecalhos_com_preenchimento_e_prioridade`, `os_erros_da_conexao`, `os_ajustes_e_o_reconhecimento`, `a_janela_e_o_incremento_zero` e `o_adeus` |
| a recusa do gate que chega ao programa como o fecho da conexão, no claro e no cifrado | `http2: o programa inteiro pelo gate`, a revogação, a contenção e o firewall no meio das correntes, e `http2: varias ao mesmo tempo` — as correntes ouviram `HTTP_CLOSED`, e não a recusa |
| o HTTP/2 exigido sem o `h2` na oferta do ALPN; o preferido sem ele; o exigido que aceita o HTTP/1.1; sem o h2c com conhecimento prévio | `http2: o programa inteiro pelo gate` e `http2: varias ao mesmo tempo`, e os casos que vão pelo TLS ou pelo h2c: as correntes pelo TLS, a revogação, a contenção e o firewall |
| o kernel fala do h2c; a política, do ALPN | `cargo xtask invariantes`: o HTTP/2 no kernel ou na política |

**As que pediram um caso.** A janela da conexão que não reabre passou na
primeira rodada: ela é de 16 MiB, e nenhum teste mandava mais que a
metade disso numa conexão. O caso novo faz três respostas de 6 MiB numa
conexão só, e confere que o servidor viu o `WINDOW_UPDATE` da conexão
mais de uma vez. O corpo sem limite também passou: os testes do limite
mandavam o `content-length`, e é ele que recusa a resposta antes do
corpo chegar — a janela da corrente abre até o limite e um byte além, e
o byte além cabia nela. O caso agora manda o corpo sem tamanho declarado:
11 bytes contra um limite de 10 são `HTTP_TOO_LARGE`, e 10 passam.

**As equivalentes.** Os dados além da janela da conexão não chegam a
existir: a janela que este lado anuncia é de 16 MiB, e ela volta a 16 MiB
assim que cai à metade, no mesmo quadro que a fez cair; um quadro tem no
máximo 16 KiB — o maior é recusado antes, como quadro, e não como
janela —, então a conta da conexão nunca fica abaixo de um quadro. A
conferência fica, para a janela que mudar de tamanho. E o segundo
`GOAWAY` que sobe a última corrente não muda nada: no primeiro, as
correntes acima da última já falharam com `HTTP_STREAM_REFUSED`, e a
conexão já não abre outras — não sobra corrente para a última nova
alcançar.

## O tecido de segurança

O NSF observa, correlaciona, interpreta, detecta, avalia o risco, abre
incidentes e **pede** respostas — e não é uma autoridade: é um principal
como os outros, `service nsf`, com o papel que a linha `servico` da
política dá a ele (`seguranca`, que enumera `audit.read`, `net.observe`,
`net.block` e `process.isolate`, cada um com o alcance escrito). Lê a auditoria e a captura
pelo gate; cada leitura e cada pedido dele é um registro da cadeia; uma
contenção que o gate recusa encerra o objetivo. O firewall nativo só
restringe, depois do gate; o DNS é um programa sobre o UDP do 9.3, e uma
resposta de DNS não dá acesso a nada — o gate decide o endereço como
decidiria o número digitado. O desenho, os contratos e o que cada consulta
`security.*` responde estão em [`docs/SEGURANCA.md`](docs/SEGURANCA.md).

### O que o exercício encontrou

- **A resolução e a conexão na mesma volta não se ligavam.** O NSF lia a
  captura antes da auditoria, e o servidor de DNS só entra em observação
  quando a auditoria mostra alguém o usando: um programa que abre a
  associação, resolve e conecta antes de uma volta do NSF — o caso de todo
  dia — tinha a resposta pulada. Agora a auditoria vem primeiro, a regra
  liga as duas nas duas ordens, e a captura só se dá por vista quando a
  leitura da auditoria alcançou a cabeça de antes dela.
- **"Precedeu" no relógio de um segundo.** A auditoria e a captura usam o
  relógio lógico, que anda de segundo em segundo: uma resolução do mesmo
  segundo, depois da conexão, contava como a que a precedeu. Agora cada
  datagrama guardado leva o número do último registro da auditoria
  (`after_record`), e a ordem é a dos registros.
- **O perfil via rajada onde só havia resolução.** Os primeiros pedidos de
  uma identidade, todos no mesmo segundo, faziam a taxa da linha de base
  em pedidos por milissegundo, e qualquer rajada depois era "quatro vezes
  a base". Agora uma duração ganha a resolução do relógio, e a taxa da
  linha de base espera trinta segundos de história.
- **O nascimento podia vir depois do primeiro pedido do filho.** O
  `user.run` e o `fork` gravavam o filho depois de ele poder rodar: o
  primeiro pedido dele chegava, às vezes, antes do registro que diz quem o
  criou. Agora o registro é gravado com o fio reservado, antes de ele ficar
  pronto — e, na suíte, quem cria espera logo depois, com o filho correndo
  noutro núcleo, para que a ordem certa tenha quem a confira. A primeira
  forma dessa espera cedia a vez, e o ARM a recusou: lá o `fork` é um
  handler de exceção, de onde não se cede; agora é uma espera ocupada.
- **A bancada de DNS travaria a pilha.** O servidor da bancada responde de
  dentro do caminho de saída, com a pilha travada, e injetava a resposta
  fazendo a pilha andar de novo — a mesma trava. Agora ele só põe a
  resposta na fila, a mesma volta da pilha a colhe, e o que é para a
  bancada não sai pela placa.
- **O programa contido fazia de quem o lançou um sondador.** Na fumaça,
  com o fio do NSF de verdade, a serial foi contida no meio da perna da
  rede: o programa `contido`, que confere de dentro a atenuação do
  manifesto, teve três pedidos recusados pelo manifesto — gravados em
  nome da serial, que é quem responde por ele —, e a regra da sondagem os
  contou como a serial sondando o próprio papel; a conexão seguinte da
  serial ao eco foi contida. Mas o papel tinha as permissões: quem não as
  declarou foi o programa. Agora a recusa do manifesto é a regra dela,
  `outside-manifest`, média — um sinal do programa —, e a sondagem conta
  só as recusas do papel.
- **A bancada de persistência esperava a própria leitura ser a última.**
  Com o NSF lendo a auditoria a cada registro novo, há quase sempre uma
  leitura dele, ainda não gravada, antes da espera. Agora a bancada espera
  o último registro que não é leitura — o journal grava em ordem, e ele
  leva os de antes.
- **O CI do ARM viu dois casos dependerem da velocidade da máquina.** Os
  casos do tecido fazem as voltas do NSF uma atrás da outra, sem a
  cadência do fio, e o balde da taxa do serviço é um só para todos: no
  kernel de release do CI, os casos de antes gastaram a rajada, e o caso
  da recusa teve as duas voltas seguintes recusadas por taxa — o NSF não
  leu nem o próprio pedido recusado. E os quatro fios que pedem junto com
  o NSF terminavam antes da segunda volta dele. Os dois se reproduzem
  aqui — o balde em três fichas antes do caso, menos pedidos por fio —;
  agora cada caso do tecido começa com o balde cheio, e os fios pedem até
  o NSF dar três voltas com eles.
- **A bancada de persistência estragava o último setor, e não o último
  registro confirmado.** Dois cenários trocam um byte no registro que a
  âncora do TPM confirmou por último — a lápide de uma revogação, a
  escrita de uma política — e esperam o journal recusado. Eles achavam
  esse registro pelo último setor com conteúdo; com o NSF lendo, a
  leitura dele depois da operação é um registro só de auditoria, que não
  avança a âncora, e o byte trocado caía nela — o rabo que o contador não
  protege, e o journal, com razão, abria. O CI do ARM viu um deles; aqui,
  uma espera de três segundos antes do corte reprova os dois. Agora a
  bancada estraga o registro que avançou a âncora por último.

### As mutações do tecido de segurança

Trinta mutações contra o que o NSF, o firewall e o DNS prometem — quinze
contra os casos da suíte de quatro núcleos, no x86, e dezesseis contra os
testes do pacote `seguranca` no hospedeiro, uma delas a mesma nos dois
lados: **trinta reprovadas**. Duas do hospedeiro sobreviveram na
primeira rodada e ganharam o teste que faltava; uma da suíte sobreviveu
até a suíte forçar a corrida que ela abre.

| Mutação | Reprovada por |
|---|---|
| a resolução não olha para trás | `dns: o resolvedor pela bancada` e `dns: a resposta nao da acesso` — o NSF não ligou o DNS à conexão recusada |
| o nascimento gravado depois de o filho poder rodar | `nsf: proveniencia pelo lancamento e pela bifurcacao` — o filho pediu antes do registro do nascimento dele (sobreviveu até a suíte esperar o filho correr noutro núcleo) |
| a saída deixa passar o fluxo barrado | `firewall: descarta o quadro sem fluxo` — o aviso da conexão derrubada saiu |
| o ICMP entra | o mesmo caso — o eco entrou, e a pilha respondeu |
| abrir não confere a regra | `nsf: contem agente e pessoa pelo mesmo caminho` e `firewall: so restringe, depois do gate` |
| o bloqueio não derruba | os mesmos dois casos — a conexão derrubada ainda respondia |
| o NSF com o papel da serial | `nsf: le pelo gate com o papel dele` e `nsf: nao e o sistema` |
| o `fork` sem registro | `politica: o processo age como o agente` e a proveniência |
| a bancada forja do próprio servidor | `dns: a resposta nao da acesso` — uma resposta forjada chegou |
| a espera depois da recusa não dobra | `nsf: le pelo gate com o papel dele` |
| o NSF não casa a própria ação | `nsf: contem agente e pessoa pelo mesmo caminho` — o incidente não dizia a decisão do gate |
| depois da recusa, planeja de novo | `nsf: a recusa encerra o objetivo` — o NSF pediu de novo |
| a leitura não avança | `nsf: le junto com quem pede` |
| a taxa da linha de base sem a história | `ueba::testes::a_rajada_de_quem_chegou_nao_e_taxa`, no hospedeiro; na suíte, a outra metade da correção — a resolução na duração da janela — a mascara |
| o NSF pede como o sistema | `nsf: le pelo gate com o papel dele` — a leitura não foi gravada como do serviço |
| a sondagem pede quatro métodos | `regras::testes::a_sondagem`, `janela_e_recarga` |
| a história pede contenção | `resposta::testes::a_contencao_so_ao_vivo_e_sem_recusa` |
| a recusa não encerra o objetivo | o mesmo teste |
| a cadeia do cofre não se confere | `evidencia::testes::adulterar_aparece` |
| o monitor não vê a lacuna | `invariantes::testes::a_lacuna_e_o_tempo` |
| o monitor não refaz o elo | `invariantes::testes::adulterado_e_desencadeado` |
| o monitor não confere o encadeamento | o mesmo teste |
| a ação sem plano passa | `a_acao_sem_plano`, `a_recusa_encerra_o_objetivo`, `da_sondagem_a_contencao_pelo_gate` |
| a resolução da mesma decisão a precede | `dns::testes::a_pergunta_e_a_resposta_casam` |
| a resolução de outro dono | o mesmo teste |
| a taxa da janela sem a resolução do relógio | `ueba::testes::a_rajada_no_mesmo_segundo_e_o_ritmo_de_sempre` (sobreviveu até o teste existir) |
| a saída contida sem incidente alto | `so_o_incidente_alto_leva_a_contencao` (sobreviveu até o teste existir) |
| a contenção para todos | `resposta::testes::a_contencao_so_ao_vivo_e_sem_recusa` |
| a regra de um agente alcança qualquer agente | `firewall::testes::o_escopo` |
| a recusa do manifesto conta como sondagem | `regras::testes::a_recusa_do_manifesto_nao_e_sondagem` |

### Segurança sem fricção

A segurança é invisível quando tudo é normal, explícita quando algo é
recusado, e decisiva quando há uma ameaça real. O incremento de
usabilidade não reabre nada do que está consolidado — o gate continua o
único ponto de decisão, e nada aqui é uma segunda autorização —; muda o
que acontece em volta da decisão. O desenho está em
[`docs/USABILIDADE.md`](docs/USABILIDADE.md).

- **Toda recusa se explica.** O erro JSON-RPC continua o mesmo — `code`,
  `message`, `data` — e ganha `explain`: o resultado (`DENY`, `CONFLICT`,
  `ERROR`), a razão (`DENY_POLICY`, `DENY_SCOPE`, `DENY_CONTAINED`,
  `RATE_LIMIT`…), se adianta repetir (`retryable`, `non_retryable`,
  `requires_authorization`, `requires_scope`, `requires_user_action`),
  quanto esperar numa taxa (`retry_after_ms`), o que fazer
  (`next_action`), uma frase para pessoas, e o número do registro da
  decisão — que o `security.explain` interpreta para quem lê a auditoria.
  O console escreve a frase e, embaixo, o código e o registro.
- **A explicação não diz o que a resposta cala.** Um recurso que não
  existe, um que é de outro e um fora do alcance são o mesmo
  `DENY_RESOURCE`, e se explicam igual, palavra por palavra.
- **Recusa, conflito e erro técnico são coisas diferentes**: o conflito
  de versão diz "leia de novo e repita", o arrendamento ocupado, "espere",
  e o erro técnico, "não conseguimos agora" — nunca "você não pode".
- **As contenções reversíveis**, cada uma com o seu inverso, pelo gate e
  em `admin.execute` com prova: `process.isolate`/`process.release`,
  `agent.suspend`/`agent.resume`, `credential.suspend`/`credential.resume`,
  e `containment.list`. Idempotentes (`already_isolated`), voláteis como
  as regras do firewall, e nunca revogação. O administrador recupera pela
  prova — até pela porta do agente suspenso.
- **O NSF observa o incomum, alerta o arriscado e só contém a violação
  com confiança alta** — a menor contenção primeiro (o destino, só para o
  dono do fluxo), o dono inteiro só se a ameaça continuar, e nada sozinho
  quando degradado. Revogar é sempre de um administrador.
- **O custo é medido**: `security.metrics` diz as decisões do gate por
  código e a latência dele, a da política e a da auditoria, as voltas do
  NSF e a parte do tempo de máquina delas, a memória do motor, as taxas
  de falso positivo, de contenção desfeita e de repetição, a latência da
  resposta, os arrendamentos soltos por causa e — desde a fase 13 — a
  conferência do código de fora da imagem.

#### O que o exercício encontrou

- **A explicação dizia o que a resposta calava.** A primeira versão lia o
  motivo da auditoria e, para um destinatário "inexistente", dizia
  "corrija o pedido" — e, para um revogado, "peça alcance". O código da
  resposta era o mesmo `DENY_RESOURCE` de propósito; a explicação
  distinguia. Os casos de vazamento das mensagens — o destinatário
  inexistente e o revogado, a mensagem de outro e a que não há — a
  pegaram. Agora um `DENY_RESOURCE` se explica de um jeito só, e um teste
  do hospedeiro confere que a frase não carrega motivo nenhum da
  auditoria (salvo o do pedido mal formado).
- **O `explain` tinha um membro `result`.** Dentro do erro, um `result`
  fazia uma recusa parecer sucesso a quem procura o resultado — dezenas de
  conferências da suíte e do `xtask` procuram `"result"`. Virou `outcome`.
- **A frase dizia a permissão onde a pessoa digitou o método.** Quem
  digitou `agent.ping` sem login ouvia "pediu agent.read". Agora a frase
  diz o que a pessoa pediu — o método — e, quando o papel não tem a
  permissão, a permissão que falta.
- **Um processo isolado ainda bifurcava** — achado na releitura. A
  contenção era conferida nos pedidos ao registro, e não no `fork`: o
  filho de um isolado nasceria livre. Agora o `fork` também pergunta, e o programa `isolavel` confere
  de dentro que, isolado, nem um filho sai.
- **A trava da contenção esperava a do escalonador** — também na
  releitura. Conferir se um
  processo isolado ainda vive, com a trava das contenções na mão, punha
  uma ordem de travas nova; a poda agora lê a lista, solta a trava e só
  então pergunta ao escalonador.
- **O caso do incomum terminava antes de o NSF ver a anomalia.** A
  mutação "a anomalia vira recusa no gate" só foi reprovada pelo `xtask`:
  o último pedido do caso vinha antes da volta em que o NSF via a
  anomalia. Agora a pessoa continua trabalhando depois de o NSF a ver.

#### As mutações da seção 39

Treze mutações, uma por propriedade que o incremento promete:
**treze reprovadas**.

| Mutação | Reprovada por |
|---|---|
| o NSF ocupado contém tudo | `resposta::testes::a_confianca_cresce_com_o_impacto` e `nsf: a sobrecarga degrada sem bloquear` |
| a anomalia vira recusa no gate | o `xtask` — o gate não lê o NSF — e `nsf: o incomum e observado, e nao contido` |
| o NSF fora do ar bloqueia tudo | o `xtask` e `recusa: diz por que e o que fazer` |
| o falso positivo revoga | `resposta::testes::revogar_e_recomendacao` |
| isolar sem volta | `contencao: o processo isolado e solto` |
| o arrendamento órfão na suspensão | `contencao: o agente suspenso e retomado pela prova` |
| um cache de decisões sem invalidação | `nsf: a recusa encerra o objetivo` — a política mudou e o gate decidiu pela velha |
| o erro técnico vira `DENY_POLICY` | `armazem: gravacao que falha nao vale` |
| o conflito vira `DENY` | `explicacao::testes::recusa_conflito_e_erro_sao_coisas_diferentes` e `armazem: os conceitos separados` |
| a recusa sem explicação | `recusa: diz por que e o que fazer` |
| a recusa sem permissão manda repetir | `explicacao::testes::a_taxonomia` e `recusa: diz por que e o que fazer` |
| a contenção executada duas vezes | `contencao: o processo isolado e solto` |
| o administrador não recupera pela porta do contido | `contencao: o agente suspenso e retomado pela prova` |

#### O gate sem cache

A seção 10 pede o gate rápido, e um cache só como otimização. A medida
decidiu: **sem cache**. Na suíte — o kernel de depuração, no QEMU sem aceleração —, uma
decisão do gate leva em média 2,1 ms; a conta da política, a única parte
que um cache pularia, 51 µs, uns 2,5% dela; o registro na auditoria, que
nenhum cache pula — toda decisão é gravada —, 475 µs. O NSF toma 67
partes por milhão do tempo de máquina, e a auditoria, 11. Na fumaça — o kernel de produção, também de depuração —, com o fio
do NSF de verdade e muita atividade concentrada: 991 decisões, o gate
1,5 ms em média, a política 49 µs, um registro 649 µs; o NSF, 81 voltas
de 60 ms, cerca de 5% de um núcleo; a auditoria, 0,75%. A fumaça escreve
os números a cada rodada. Um cache de decisões teria de ser
invalidado por toda troca de política, de papel, de registro e de
contenção — e a mutação "um cache sem invalidação" mostra o que acontece
quando se esquece um deles: a política muda e o gate decide pela velha.
Sem ganho a medir, não há o que pagar com esse risco.

#### Decisões pendentes

- **A expansão temporária de alcance** (seção 12): hoje o alcance é do
  papel, e o que muda o papel é `policy.write` e `policy.assign`, com
  prova, até a próxima mudança. Uma expansão **temporária, por
  titular** — "esta pessoa, este recurso, por uma hora" — é um conceito
  que a política não tem: uma entrada com prazo, de uma identidade e não
  de um papel, que vence pelo tempo lógico e sobrevive a um boot. Isso
  não se infere das invariantes; fica proposto, e não implementado, até
  uma decisão.

## O tempo

Três relógios, separados: o **monotônico**, que conta desde o boot e mede
arrendamentos, sessões, taxas e esperas — nenhuma fonte o toca —; o
**civil**, a melhor estimativa da hora UTC, com a incerteza dela e um
estado; e o **lógico**, `max(piso, civil)`, que nunca volta e carimba a
auditoria. O civil autenticado vem do Roughtime (RFC 10049, versão 1, e só
ela): uma resposta assinada prova que o servidor viu o nosso pedido, e só o
**acordo de pelo menos duas chaves** move a hora. Nenhuma decisão de
autorização lê o civil nem o lógico.

Ele chegou em passos. As contas — a moldura, a conferência da resposta, o
quórum e a disciplina — estão no pacote `hora`, puro e testado no
hospedeiro. A superfície na política e no gate — as duas permissões, o
serviço e o papel, o registro das fontes — veio em seguida. Por cima dela,
sem tirar nem pôr, o kernel tem o relógio civil, o lógico por ele, e o
**serviço de hora**: um fio que consulta as fontes do registro pelo gate e
entrega ao kernel o que elas responderam. E a **bancada de tempo**
(`cargo xtask tempo`) põe tudo isso à prova pela rede de verdade: três
servidores de Roughtime no hospedeiro, escritos à parte do pacote `hora`, e
a imagem de produção sincronizando por eles — com o RTC atrasado e
adiantado, e com as fontes pulando, atrasando, calando, divergindo e
voltando. A fumaça e a bancada de persistência continuam sem servidor: a
imagem faz as rodadas, não recebe resposta, e o civil fica no RTC.

### Os relógios no kernel

**A régua** (`hora::contador`). O civil não mede o tempo pelos tiques do
timer: tique perdido não volta, e o emulador junta interrupções quando o
processador emulado fica sem vez no hospedeiro — 5% de perda são 51 s de
erro entre duas rodadas de 1024 s. Mede pelo contador de ciclos, que é
lido, e não interrompe: no ARM, com a frequência que o processador declara
(`CNTFRQ_EL0`); no x86, com a do TSC medida no boot contra o canal 2 do PIT
— um décimo de segundo, até cinco tentativas, e vale a primeira com erro
de até 200 ppm, que entra na deriva máxima do civil. Sem nenhuma das duas,
a régua são os tiques, com 5% de deriva: o civil vence o teto da incerteza
em minutos, e o `system.info` diz `ticks`. A régua nunca devolve menos do
que já devolveu, em núcleo nenhum. O relógio do kernel continua sendo a
régua das durações; o serviço só mede a taxa dele contra o contador
(`mono_ppm`), e não o corrige.

**O civil** (`hora::civil`). Uma instância só da disciplina do pacote,
atrás de uma trava folha. Antes do primeiro acordo, é o RTC: lido no boot e
relido no máximo uma vez por segundo, fora da trava, e só para a frente —
um RTC que ainda não virou o segundo, ou que alguém atrasou, não faz o
civil voltar. Depois, **só dois caminhos o movem, e os dois atrás do
gate**: o tratador de `time.sync`, na entrega da última fonte de uma
rodada, e o de `time.confirm`, dentro de `admin.execute`. Ninguém mais lê o
RTC: o `system.info` lê o cru pelo civil.

Os estados são os do desenho: `rtc`, antes de qualquer acordo;
`sincronizado`, até 2048 s depois do último; `holdover`, passada a janela,
com a incerteza crescendo pela deriva máxima da régua; e `vencido`, com a
incerteza acima do teto do registro (60 s, por padrão). Três marcas
acompanham o estado: **pendente** — um salto espera confirmação —,
**divergente** — o último acordo deixou fontes de fora, ou não houve acordo
porque elas não se tocam — e **adiantado** — o lógico está à frente do
civil, depois de um salto para trás.

A disciplina é a do pacote, com os tetos do registro. Com o desvio Δ entre
o meio do acordo e o civil, e a incerteza u do acordo: |Δ| ≤ u, nada se
move; até o limiar — o maior entre 10 s e 2u —, o ajuste **gradual**, no
máximo 5% mais rápido ou mais devagar, e nunca para trás; acima, um
**salto**, só depois de duas rodadas seguidas que concordam no desvio, a
pelo menos 4 s uma da outra. Mas o salto para a frente além do teto
(um dia, por padrão), contado do maior entre o civil e o piso do lógico, e
o salto para trás depois da primeira sincronização que a régua não explica
— fora do envelope — ficam **pendentes**: só `time.confirm` os aplica.

**Quando o civil volta.** Em três casos, e só neles, sempre pelo acordo de
pelo menos duas chaves de fontes do registro: na primeira sincronização do
boot, quando a hora autenticada troca a do RTC — um salto, em duas rodadas
seguidas —; depois dela, num salto para trás **dentro do envelope** — o
acordo toca o intervalo do civil com a incerteza dele, e o civil é
corrigido para dentro da própria incerteza —, também em duas rodadas
seguidas, sem confirmação, como qualquer salto que a régua explica; e na
confirmação de um salto para trás pendente, o de fora do envelope. O ajuste
gradual nunca volta. Nenhum outro salto para trás acontece: o de fora do
envelope fica pendente até alguém o confirmar. É a disciplina fechada no
T7.1, e o desenho diz o mesmo. **O lógico não volta em caso nenhum** — nem
nesses três.

**O lógico** (`persistencia::agora`): `max(piso, civil em segundos)`, com o
piso no journal. Antes da primeira sincronização é exatamente o de antes,
porque o civil é o RTC; depois, segue a hora autenticada. Nunca volta:
depois de um salto do civil para trás, ele fica no piso — `adiantado` — até
o civil passar. Os carimbos da auditoria e os prazos das mensagens andam
nele.

**Nenhuma decisão lê o civil nem o lógico.** O gate decide pelo relógio do
kernel; o estado do relógio não concede nada. O `cargo xtask invariantes`
confere: em `autorizacao.rs`, o lógico só dentro de `auditar` — o carimbo —,
e nunca `crate::hora::`, `civil_s(` ou `relogio::agora(`.

### A superfície no gate

**Duas permissões.** `time.sync` autoriza **apresentar evidência**, e não
escolher a hora: pedir ao kernel o pedido do Roughtime para uma fonte do
registro, e entregar a resposta que chegou — o kernel a confere contra o
que ele mesmo emitiu. É sensível — nenhum papel a recebe pela inclusão de
outro — e não é administrativa: o serviço de hora a exerce pelo gate, sem
prova. `time.confirm { round }` aplica um salto que o quórum já indicou e
que ficou pendente — acima do teto, ou para trás fora do envelope —; é
administrativa: só por `admin.execute`, com a prova de um administrador
cujo papel a tem. `round` é a rodada que pediu o salto — a que o
`system.info time` mostra em `pending_round` — e só identifica a evidência
que o administrador conferiu: não é hora, nem ajuste, nem autoridade, nem
escolha do relógio. Outra rodada, ou nenhum salto pendente: `CONFLICT`, e
nada se move. Não recebe hora nenhuma.

| | `time.sync` | `time.confirm` |
|---|---|---|
| `observador`, `operador` | não | não |
| `tempo` (o serviço de hora) | sim | não |
| `sistema` | sim | não |
| `administrador` (o teto) | sim | sim, com prova |
| `seguranca` (o NSF) | não | não |

**Três operações.** `time.request {source}` e `time.sync {id, anexo}` são
comandos, decididos pelo gate com `time.sync` e gravados como qualquer
outro; `time.confirm {round}` é operação administrativa, dentro de
`admin.execute`.
O que cada uma faz depois do gate está
[mais abaixo](#o-que-cada-operação-faz-depois-do-gate).

**O serviço `hora` e o papel `tempo`.** O serviço tem identidade própria,
como o NSF: `Autoridade::Servico(Servico::Hora)`, com o papel da linha
`servico hora tempo`. O papel `tempo` enumera duas permissões — conectar,
com `net.connect`, às três fontes da bancada, `udp:10.0.2.2:5319`,
`:5320` e `:5321`, e `time.sync` — e nada mais: não lê arquivo, não lança,
não lê a auditoria, não confirma salto, e não inclui o `sistema`. A linha
só vem da imagem, e só na política padrão: na de emergência, o serviço não
tem papel, e o civil fica no RTC. A taxa é a do papel, num balde só do
serviço — cada serviço o seu: o de hora que pede demais não gasta a ficha
do NSF, nem o contrário.

**O registro `/etc/duke/tempo`.** As fontes em que o civil confia, da
imagem, como o registro de editores:

```
fonte bancada-a udp:10.0.2.2:5319 ed25519:<raiz pública em hexadecimal>
fonte bancada-b udp:10.0.2.2:5320 ed25519:<…>
fonte bancada-c udp:10.0.2.2:5321 ed25519:<…>
quorum 2
salto 86400
incerteza 60
```

Até oito fontes, cada uma com nome, destino UDP na forma normal da política
e a raiz Ed25519 dela — uma chave fora da curva ou de ordem pequena é
recusada na leitura; nome, destino e chave não se repetem. `quorum` é
obrigatório e vai de 2 a 8: **k ≥ 2 sempre**. Com k maior que o número de
fontes, o registro vale e o relógio nunca se move — uma fonte isolada é
conferida e auditada, e não move nada. `salto` — o teto do salto automático
para a frente — vai de 1 s a um dia; `incerteza` — o teto da incerteza
antes de a hora vencer — de 10 s, o maior raio aceito, a 10 min. Sem as
duas linhas, um dia e 60 s. **Qualquer erro recusa o registro inteiro**,
com a linha; recusado ou ausente, não há fonte nenhuma — e nenhuma
autorização a mais. As chaves privadas das fontes da bancada ficam em
`target/chaves/`; a imagem recebe só as públicas.

**A coerência com a política.** O registro diz em quem confiar; a política,
com quem o serviço fala. O `xtask` não gera a imagem se os dois não disserem
o mesmo, nos dois sentidos: cada fonte no alcance do `net.connect` do papel
do serviço, o papel alcançando só as fontes, o quórum alcançável, e
`time.sync` só no `tempo`, no `sistema` e no `administrador`, `time.confirm`
só no `administrador`. O boot confere de novo, contra a política em vigor, e
avisa cada fonte que o serviço não alcança. A coerência é conferência de
configuração, e não autorização: quem impede o serviço de falar com uma fonte
sem destino na política é o gate, a cada `net.connect` — e um `policy.write`
que corte uma fonte vale na decisão seguinte, sem tirar o registro.

**Nenhum outro caminho.** `Servico::Hora` só aparece no gate;
`Permissao::TimeSync` só nos dois comandos; `Permissao::TimeConfirm` só na
operação administrativa — o `cargo xtask invariantes` confere os três, e a
política da imagem. Revogar `time.sync` do papel `tempo` recusa no gate o
pedido seguinte do serviço, e também a entrega de uma resposta: a
continuação de uma operação já começada é outra decisão, e não uma exceção
do serviço.

A suíte confere, pelo gate de verdade: o registro do boot e o leitor dele
recusando k = 0, k = 1, a chave que não serve e o destino TCP; o serviço
pedindo com o papel dele, gravado como `service`/`hora`/`tempo`; a fonte
fora do registro e o registro ausente; o transporte só até as fontes; o
serviço não sendo o sistema — sem a linha, `DENY_ROLE`; incluindo o
`sistema`, sem as sensíveis —; pessoa e agente do mesmo papel decidindo o
mesmo, com e sem `time.sync` delegado, e os não autenticados recusados;
`time.confirm` sem prova, com a prova de outra coisa ou de outra rodada,
por quem não é administrador e por um administrador sem a permissão; sem
a rodada, com uma rodada que não é inteiro sem sinal, com a mesma chave
duas vezes e com uma hora, sozinha ou ao lado da rodada; a revogação e a
devolução por `policy.write`; o balde de cada serviço; e nenhum caminho de
`time.sync` mudando política, registro ou credencial. O que o relógio e o
serviço acrescentam está
[mais abaixo](#o-que-a-suíte-a-fumaça-e-a-bancada-conferem).

### O serviço de hora

O fio `hora`, com `Autoridade::Servico(Servico::Hora)` e o papel da linha
`servico hora tempo` — como o NSF: cada passo é um pedido JSON-RPC ao gate,
decidido e gravado, e nenhum passo a menos que um processo. Ele não toca o
relógio: só entrega o que as fontes responderam, e quem decide é o
tratador de `time.sync`. Sem registro de fontes, não sobe.

Uma rodada, fonte por fonte, na ordem do registro:

1. `time.request {source}`: o pedido v1, de 1024 bytes, e o id dele;
2. `net.connect {to}`: a associação UDP com o destino da fonte — o gate
   decide pelo alcance do papel `tempo`, e o firewall pode cortá-la;
3. `net.send`, com o pedido no anexo;
4. `net.recv` com espera até o prazo do pedido — 2 s, menos uma margem —:
   cada datagrama que chega vai inteiro, como chegou, a `time.sync`. Uma
   recusa não consome o id: a fonte tem até quatro entregas;
5. `net.close`;
6. sem resposta aceita nem recusada de vez, `time.sync {id}` sem anexo: o
   aviso de que ela não veio.

A entrega da última fonte fecha a rodada. Uma recusa do gate — sem
`time.sync`, sem a linha `servico`, a taxa — encerra a rodada: nada tenta
outro caminho, e a recusa fica gravada. O intervalo é o do desenho: 2 s
entre rodadas até sincronizar, dobrando até 64 s com as fontes caladas;
sincronizado, 64 s dobrando até 1024 s; uma falha depois disso volta a
64 s; um candidato a salto pede a rodada seguinte depois da separação
mínima.

Entre as rodadas, e esperando um datagrama, o fio fica **bloqueado** — fora
do rodízio, até o tique da próxima rodada ou o evento da conexão
(`fios::bloquear_em`) —, e não descansando a cada interrupção, como o NSF,
o coletor e a rede. A primeira versão descansava, e a fumaça do ARM mostrou
o preço: quem descansa continua pronto, o fio da hora era o quinto numa
máquina de quatro núcleos, nenhum núcleo dormia mais, e cada `video.sample`
do canal passou de 210 ms a 500 ms — a sonda da tela não conseguia
fotografar a barra no mesmo segundo. Bloqueado, voltou a 216–272 ms. O
`cargo xtask invariantes` confere quem ainda descansa.

E quem volta da cessão em `bloquear_em` volta **rodando**, antes de
conferir o futuro de novo. O primeiro núcleo não tem ocioso — o fio do boot
faz as vezes dele —, e quem estaciona ali sem mais ninguém pronto não sai
do núcleo: a escolha o deixa correr, ainda esperando, e o futuro conferido
de novo pode ficar pronto sem o waker — o prazo que o tique de outro núcleo
venceu antes de o tique deste acordar os dormentes; o `Dormir` pronto já
devolveu a vaga dele, e ninguém mais o acorda. Marcado esperando, o fio
saía de circulação para sempre na primeira troca. Foi o CI que achou, duas
vezes. A primeira, a troca de saída: a suíte do ARM carregada pelo
firmware UEFI parou dez minutos em `hora: os estados e a recuperacao`, na
rodada com as três fontes mudas — o fio da suíte é o do boot, fixo no
primeiro núcleo —, e o conserto pôs o fio de volta a `Rodando` ao sair. A
segunda, no fechamento do tempo autenticado (T7.6), o quantum que vencia
entre a conferência e essa volta, com outro fio pronto no núcleo: a suíte
do ARM em release perdeu o fio da bancada de hora no meio de `hora: cada
resposta ruim e um veredito`, e dali em diante toda rodada pela rede
fechou sem resposta de fonte nenhuma — treze casos reprovados. Agora o fio
só fica marcado esperando entre estacionar — com a trava do escalonador na
mão e o waker do `Pending` registrado — e a troca: uma troca no meio do
caminho o tira esperando com o waker no lugar, e o waker o devolve.

### A rodada

Uma rodada é de **um principal** — a autoridade que o gate decidiu, e não o
fio nem um PID. O serviço, o sistema, um agente ou uma pessoa com
`time.sync` fazem cada um a sua, pelas mesmas operações:

- `time.request` da primeira fonte abre uma rodada nova, e larga a de antes
  do mesmo principal, com os pedidos dela;
- a fonte seguinte só é pedida depois de a anterior entregue — aceita,
  recusada de vez, sem resposta ou vencida —, e o nonce dela é
  H(o pacote inteiro da última resposta aceita da rodada ‖ 32 bytes
  aleatórios): a resposta de uma fonte prova que a anterior já tinha
  respondido. Sem resposta aceita ainda, o nonce é o próprio aleatório, do
  gerador. Começar do meio, pular uma fonte ou pedir a seguinte com a
  anterior aberta é recusado;
- pedir de novo a fonte em curso substitui o pedido dela, se ela ainda não
  foi aceita — o de antes se fecha, e a entrega dele não acha nada —: uma
  resposta autêntica não se troca por outra;
- a entrega da última fonte fecha a rodada: as amostras aceitas, levadas ao
  mesmo instante pela régua, vão ao quórum de pelo menos k chaves do
  registro, e o desfecho vai à disciplina.

Os pedidos moram em duas tabelas: a do serviço de hora, só dele, e a de
todos os outros — quem pede demais não toma a vaga do serviço. Cada uma com
16 abertos, 8 por principal e 4 entregas recusadas por id; o id é da
tabela, e a busca é sempre pelo par (principal, id): o id de outro, ou o
de um pedido já consumido, não acha nada. As rodadas de outros principais
abertas ao mesmo tempo são no máximo quatro; a do serviço tem lugar só
dela.

**A política no meio da rodada.** Uma rodada aberta sob uma política vale
só sob ela: uma troca da política em vigor — um `policy.write`, o papel da
serial num `policy.assign` — larga as rodadas em curso e os pedidos delas.
O que muda sem trocar a política — o papel de um agente, a chave revogada,
a sessão de pessoa que acabou — não larga nada: o pedido seguinte é
recusado pelo gate. No fechamento, o
ponto de commit, as duas coisas são conferidas de novo: a versão da
política — uma escrita pode chegar enquanto as assinaturas da última
resposta são conferidas — e a decisão do gate, refeita pela política e pelo
registro de agora (`autorizacao::reconfirmar`), que vê também o que não
muda a versão: a sessão de pessoa que acabou, a chave revogada. Se uma das
duas não vale, a rodada é descartada, e o descarte gravado — nada dela
chega ao civil.

**A vez da hora.** As tabelas ficam sob uma trava do fio, e não do núcleo:
conferir uma resposta custa duas assinaturas Ed25519 — milissegundos no
emulador —, e isso não se faz com as interrupções mascaradas. Quem espera
cede a CPU. Nunca é pedida com uma trava de núcleo na mão, e a conferência
da ordem das travas a vê como uma classe. A versão da política é lida com
a vez na mão: lida antes, podia ser de antes de uma troca que outro fio já
viu, e largaria as rodadas abertas sob a nova.

### O que cada operação faz depois do gate

- **`time.request {source}`** responde `{id, source, to, round, request}`,
  com o pedido em base64. Fonte fora do registro — ou sem registro —, fora
  da ordem, com a anterior aberta ou já aceita: `INVALID_REQUEST`; a tabela
  cheia, `DENY_QUOTA`; sem entropia, `ENTROPY_UNAVAILABLE`. Cada recusa
  depois do gate fica gravada como execução da decisão.
- **`time.sync {id, attachment}`** confere a resposta contra o registro do
  pedido, e nunca contra o que quem entrega diz dela. Responde o veredito —
  `aceita`, com `midp`, `radi` e `rtt_ms`; a recusa pelo nome (`moldura`,
  `estrutura`, `tipo`, `versao`, `nonce`, `outro_pedido`,
  `assinatura_da_delegacao`, `assinatura_da_resposta`,
  `fora_da_delegacao`, `raio`), com a tentativa; `sem_resposta`, sem anexo;
  `vencida`, depois do prazo — e, na última fonte, a rodada: o desfecho do
  quórum, a cobertura, a incerteza, o efeito, o estado antes e depois, a
  marca de divergência, o salto pendente. Um id que não está aberto para
  quem entrega — a resposta sem pedido, o pedido de outro principal, a
  mesma resposta duas vezes — é `INVALID_REQUEST`.
- **`time.confirm {round}`**, dentro de `admin.execute`, com a prova de um
  administrador cujo papel a tem: confere que o salto pendente é o da
  rodada `round`, e só então o aplica — o meio do acordo daquela rodada,
  levado até agora pela régua — e grava a rodada, o civil e o lógico antes
  e depois. A conferência e a aplicação são uma coisa só, com a trava do
  civil — a mesma com que uma rodada nova troca o pendente —: ou a
  confirmação vê o pendente que nomeou, ou vê o de outra rodada e não
  aplica nada. Sem salto pendente, ou com o de outra rodada — a que trocou
  o que o administrador leu —, `CONFLICT`, e nada se move, nem o civil nem
  o lógico; a decisão e o conflito ficam gravados, com a rodada pedida e a
  do pendente. Os parâmetros são `{"round": N}` e nada mais: sem a rodada,
  com uma que não é inteiro sem sinal, com a mesma chave duas vezes ou com
  qualquer outro campo — uma hora digitada —, `INVALID_ARGUMENT`. Nunca
  uma hora de quem confirma.

**`system.info`** tem o objeto `time`: o estado, o civil em ms, a
incerteza, o salto pendente e a rodada que o pediu — a evidência que quem
confirma confere antes —, as marcas, o lógico e quanto ele está adiantado;
as fontes em resumo (quantas, o quórum, se o registro move o relógio); as
rodadas — fechadas, com e sem acordo, perdidas, saltos confirmados, as
abertas, e a última, com o veredito de cada fonte —; a régua (origem,
frequência, erro, deriva); a taxa do monotônico; e o custo da conferência.
Nenhum nonce, nenhum id, nenhuma resposta: os pedidos são de cada
principal. E nenhum parâmetro: não é mecanismo de ajuste.

### A auditoria

Cada operação grava a decisão do gate, com o titular, o agente e o papel —
o serviço como `service`/`hora`/`tempo` —, e o que ela fez depois:

| Registro | Recurso | Detalhe | Código |
|---|---|---|---|
| `time.request` recusado depois do gate | a fonte pedida | o motivo | `CONFLICT` (a ordem), `INVALID_ARGUMENT`, `DENY_QUOTA`, `ERROR` |
| `time.sync`, o veredito | a fonte e o resumo do pacote entregue | `aceita midp … radi … rtt …`, `recusada <nome> n/4`, `sem_resposta`, `vencida` | `ALLOW`; `DENY_REPLAY` (nonce, outro pedido); `DENY_CREDENTIAL` (as assinaturas, a delegação); `INVALID_ARGUMENT` (a forma, o raio); `ERROR` |
| `time.sync`, o desfecho da rodada | `civil <antes>><depois> logico <antes>><depois> <estado>><estado>` e as marcas | `r<n> <desfecho>` — a cobertura, as aceitas, o desvio e a incerteza, ou a maior cobertura —, e o efeito | `ALLOW`; `CONFLICT` (pendente, divergente); `ERROR` (sem acordo) |
| `time.sync`, a rodada descartada | `civil` | `r<n> descartada: <motivo>` | `DENY_POLICY` |
| `time.sync` sem pedido aberto para quem entrega | `id <n>` | o motivo | `INVALID_ARGUMENT` |
| a confirmação, `time.confirm` em `admin.execute`, executada | `salto <desvio> r<n> civil <antes>><depois> logico <antes>><depois>` | | `ALLOW` |
| a confirmação recusada depois da decisão | | `nenhum salto de hora pendente`, ou `r<pedida> nao e a rodada do salto pendente, r<pendente>` | `CONFLICT` |

Dois registros na última fonte, e não um: o detalhe tem teto de 96 bytes no
codec, que não muda. Nunca um corpo — o pedido, a resposta e o nonce não
entram na auditoria; o resumo do pacote, sim.

**O NSF** lê o tempo nesses registros, e nunca num relógio: o
`security.status` ganhou o objeto `time` — o estado e as marcas da última
rodada, quantas fecharam, e as respostas pela classe do veredito. Só
observa: nenhuma regra de tempo, nenhuma ação. O serviço de hora, como
titular, é observado e nunca alvo — nenhuma regra nem perfil o conta, e
nenhuma resposta do NSF chega a ele nem às fontes dele: quem forja
respostas ruins não faz o NSF cortar a fonte legítima.

### A pilha

A conferência de uma resposta roda no fio de quem entrega, no fundo do
despacho do gate — e o fio do serviço de hora tem a pilha de um fio
qualquer, 60 KiB. A primeira rodada honesta da suíte, no perfil de
depuração, derrubou o kernel com uma falta dupla: a pilha estourou. No
perfil de depuração cada temporário tem lugar próprio na pilha, e uma
rodada — o registro, o veredito de cada fonte, o pedido de 1 KiB — tem
alguns KiB, copiados a cada movimento. A correção não aumentou a pilha:
o que é grande anda em caixa — a rodada mora numa do começo ao fim, o
fechamento a leva consigo, a entrega devolve só a fonte —, e o fio do
serviço orquestra em passos pequenos, um quadro de cada vez. Um caso da
suíte mede a marca d'água da pilha de um fio novo que faz a rodada inteira,
e exige folga de um quarto: no perfil de depuração, 42 048 bytes dos
61 440 no x86 e 42 896 no ARM — 68% e 70%.

### O que a suíte, a fumaça e a bancada conferem

A suíte tem três servidores de Roughtime dentro do kernel de teste, com
chaves sorteadas a cada caso, e vinte casos `hora:` além dos oito `tempo:`
do passo anterior: a régua e os três relógios; uma rodada honesta ponta a
ponta pelo gate — a primeira sincronização, cada passo gravado como do
serviço, o `system.info` sem nonce nem resposta —; cada resposta ruim como
um veredito da classe dela — o lixo, a versão, o nonce de outro pedido, a
delegação de outra chave, a assinatura que não fecha, a árvore sem o
nosso pedido, a janela da delegação, o raio, o datagrama grande, a
resposta repetida —, sem mover o relógio; as entregas que não são de quem
entrega — sem pedido, o pedido de outro principal, a mesma resposta duas
vezes, as quatro tentativas, depois do prazo —; os nonces encadeados e a
ordem da rodada; k ≥ 2 — uma fonte e k − 1 fontes não movem, duas
coerentes movem —; as fontes divergentes e a interseção vazia; a
disciplina — o ajuste gradual no teto de 5% e nunca para trás, o salto em
duas rodadas, o salto acima do teto pendente até a confirmação, o salto
para trás fora do envelope com o lógico parado no piso —; a confirmação que
nomeia a rodada — a corrida do pendente trocado: a rodada A lida no
`system.info`, a B no lugar dela, a confirmação de A em conflito, gravada
e sem mover relógio nenhum, como a de uma rodada sem pendente e a de uma
que não houve; a malformada, recusada antes do civil; e a de B aplicando o
salto de B, e não o de A —; a confirmação pela cadeia inteira, com o salto
pendente esperando — sem prova, a prova de outra rodada, o administrador
sem `time.confirm`, a credencial revogada antes e no meio, a política sem
`time.confirm` antes e no meio, nada se movendo, e o `policy.write` que
muda outra coisa sem trocar a evidência —; os estados e a
recuperação; a resposta atrasada na rede — com o fio da rodada fora do
rodízio enquanto espera —; a revogação e a política no meio da rodada; o
ponto de commit; a rodada na pilha de um fio; a concorrência; e nenhum
caminho fora do gate. E um caso do escalonador, `fios: quem bloqueia sai do
rodizio`: o fio bloqueado num prazo fica esperando, sem ser escalonado, até
o tique; o waker o devolve; e o aviso que chega antes do sono não se perde.
E outro, `fios: quem volta do bloqueio volta rodando`: o fio da suíte, no
núcleo sem ocioso, bloqueia duzentas vezes num futuro que fica pronto sem
acordar ninguém, e volta de cada uma rodando — com os outros fios presos a
outro núcleo, ele não tem por quem ser trocado, e o caso exige ter passado
pela volta sem sair do núcleo. E `fios: a preempcao na conferencia nao
perde o fio`: um fio preso ao núcleo da suíte estaciona sem sair dele e,
na segunda conferência do futuro, acorda a suíte e gira até ela rodar — o
que só acontece se o quantum o tirar do núcleo ali dentro —; ele tem de
voltar da conferência e de `bloquear_em`, e confere que não saiu do núcleo
entre as duas conferências, o caminho do defeito.
**A concorrência**: o serviço e o sistema
fazem rodadas ao mesmo tempo sobre as mesmas fontes, cada um com os
pedidos dele, enquanto outros fios leem o civil e o `system.info time` e o
NSF lê a auditoria — todas fecham com o acordo das três fontes, o civil
lido nunca volta, os carimbos da auditoria nunca descem, e no fim não
sobra pedido nem rodada aberta. E a confirmação contra uma rodada nova: um
fio faz rodadas sem parar, cada uma trocando o pendente pelo dela, enquanto
o caso lê o `pending_round` e confirma — logo, na corrida, ou depois de
mais duas rodadas fecharem —; cada confirmação aplica o salto da rodada que
nomeou, e a resposta e o registro a nomeiam, ou é um conflito gravado, e o
civil e o lógico não saltam; as atrasadas são sempre conflito de outra
rodada, e o lógico nunca volta. E os consumidores (ver [Os consumidores
da hora](#os-consumidores-da-hora)): o `system.info time` lido pela regra
dos programas em cada estado, e três programas `validade` conferindo pelo
civil enquanto rodadas e o NSF correm ao lado.

A fumaça roda a imagem de produção, sem servidor: a serial faz uma rodada
inteira pelo canal de verdade — o pedido de 1024 bytes de cada fonte, na
ordem, a fonte de fora, fora da ordem e com a anterior aberta recusadas, a
entrega sem resposta — e a rodada fecha sem acordo, com o civil no RTC; o
operador de uma porta é recusado; o `system.info time` diz o estado, as
fontes, as rodadas perdidas e a régua, sem pedido nenhum, e nenhuma rodada
pendente; `time.confirm {round}` com a prova do administrador e a rodada da
serial acha `CONFLICT` — nenhum salto pendente — e recusa o pedido sem a
rodada, a hora digitada e a hora ao lado da rodada; e a
auditoria tem cada decisão, o desfecho da rodada da serial e o serviço de
hora pedindo pelo gate como ele mesmo. O `cifrado` diz que conferiu o TLS
pela hora `rtc`, não autenticada — a do tempo lógico.

E a fumaça sobe a mesma imagem de produção mais uma vez, num boot só dela,
agora com o servidor Roughtime da bancada de tempo respondendo nas três
fontes do registro (`tempo::na_fumaca`), e confere a cadeia inteira de
fora, na ordem em que ela acontece: o boot, a rede e o endereço do DHCP,
pelo log; a primeira rodada do serviço depois do endereço; as três
respostas aceitas, cada uma pela chave fixada no registro, e o acordo 3/3
acima do quórum; o civil `sincronizado`, com a hora do hospedeiro dentro
da incerteza; o lógico com o civil, e o mesmo no `persistence.clock`, que
o journal grava como piso; o programa `validade`, de verdade, pelo civil —
`bancada.duke` aceito, `vencido.duke` `TLS_EXPIRED`, `futuro.duke`
`TLS_NOT_YET_VALID`, o `Max-Age` vencendo 12 s depois —; o NSF vendo
`sincronizado`, sem incidente, sem marca, o lógico andando, a contenção
por taxa ativa e nenhum pedido; e a auditoria com cada passo do serviço
`ALLOW`, o fechamento 3/3 da rodada, e o `validade` lendo a hora pelo
gate (`system.info`) e conectando, sem um pedido `time.*`. Do lado do
servidor, só pedidos de 1024 bytes, todos respondidos. A fumaça com
teclado USB e a com virtio-gpu não repetem esse boot. A bancada de
persistência confere o lógico através de reboots: com o RTC voltado para trás do piso, o civil é
o RTC e o lógico fica no piso, `adiantado`; com o RTC adiante, o lógico
anda com ele.

### A bancada de tempo

`cargo xtask tempo` põe o caminho inteiro do Roughtime à prova pela rede de
verdade. Para cada cenário, sobe três servidores no hospedeiro — as três
fontes do registro da imagem, uma porta UDP do loopback para cada uma,
`5319` a `5321` — e uma máquina da imagem de produção, com o estado zerado
e o RTC onde o cenário pede (`-rtc base=`). O registro diz
`udp:10.0.2.2:5319` a `5321`, e a rede do emulador leva esse endereço ao
loopback do hospedeiro: a premissa do desenho, conferida antes de existir
servidor, com um ouvinte que só anotava — a cada rodada, os três pedidos de
1024 bytes, um por fonte, na ordem do registro. O pedido do serviço de hora
sai pelo gate, pela placa e pela rede do emulador; a resposta volta pelo
mesmo caminho, passa pelo firewall de entrada e chega ao tratador de
`time.sync`, que a confere, junta as fontes no quórum e move o civil pela
disciplina.

**O servidor** (`xtask/src/servidor_de_hora.rs`) é escrito à parte do
pacote `hora`: a moldura, as etiquetas na ordem, a árvore de Merkle, o
`SRV` e as duas assinaturas, sobre o `sha2` e o `ed25519-dalek` direto. A
raiz de cada fonte é a privada de `target/chaves/`, a mesma cuja pública a
imagem fixa; a delegada é sorteada a cada subida e nunca gravada, e a raiz
assina a delegação uma vez. Só os testes dele usam o pacote `hora`, e para
conferir: a resposta passa pelo leitor do kernel, a de um lote fecha a
árvore, e o desenho dela — as etiquetas, a ordem e os tamanhos, em cada
nível — é o da resposta do vetor da RFC 10049. O `cargo xtask invariantes`
confere que o resto do servidor não nomeia o pacote. O pedido que não é o
de um cliente da versão 1 — menor que 1 KiB, sem a moldura, de outro tipo,
sem a versão 1, com o `SRV` de outra raiz, sem o nonce — fica sem
resposta. Cada datagrama vira uma linha do diário do servidor — quando
chegou, de que fonte, o tamanho e o que se fez com ele —: o lado de fora da
rodada, que a bancada confronta com o que o kernel diz ter aceitado.

**Os modos.** Cada fonte responde num modo que o cenário troca com a
máquina ligada: a hora deslocada, o raio, o atraso da resposta, calada, o
lote — a resposta numa árvore de 2, 8 ou 64 folhas, com o pedido na
última, e o caminho de 1, 3 ou 6 resumos até a raiz assinada —, e forjada
— a resposta honesta assinada por uma chave que a delegação não nomeia.

**Nenhuma autoridade nova.** A bancada fala com a máquina pela serial, como
a fumaça. O que ela muda lá dentro passa pelo gate: `net.block` e
`net.unblock` com o papel da serial; `policy.write` e `time.confirm` em
`admin.execute`, com a prova do administrador da imagem. O servidor não
fala com o kernel: responde a quem pergunta.

| Cenário | Montagem | O que se confere |
|---|---|---|
| As fontes honestas | o RTC na hora | a primeira rodada sincroniza — acordo 3/3, a hora do hospedeiro dentro da incerteza —, e a seguinte não move nada; cada passo do serviço na auditoria, `ALLOW`; o programa `validade` confere pelo civil, autenticado — `bancada.duke` aceito, `vencido.duke` e `futuro.duke` recusados, o `Max-Age` vencendo —; o NSF lê as seis respostas aceitas, sem incidente, sem marca, o lógico andando, a contenção por taxa ativa e nenhum pedido |
| O lote | árvores de 2, 8 e 64 folhas | as três respostas aceitas pelo caminho de Merkle, com o `INDX` 1, 7 e 63 |
| Uma fonte divergente | a segunda dez minutos à frente | acordo 2/3, `divergente` na rodada e no NSF, o civil nas outras duas; o NSF abre o incidente `time-source-divergent` e não faz nada com a fonte — nenhuma ação no incidente, nenhum pedido ao gate —; o programa `validade` confere pelo civil, autenticado, e diz a marca; a marca sai quando ela volta |
| Uma fonte forjada | a segunda assina com uma chave que a delegação dela não nomeia | o kernel recusa a resposta pela assinatura — a entrega na auditoria, `DENY_CREDENTIAL`, `recusada assinatura_da_resposta` —, e o acordo é das outras duas, 2/2; o NSF abre o incidente `time-source-bad-signature`, com a fonte, e não faz nada com ela — nenhuma ação, nenhum pedido —; quando ela volta a assinar com a delegada, 3/3 |
| O atraso | depois de sincronizar, respostas em 0,8 s, 1,5 s e 2,5 s | o RTT de cada uma na auditoria, e a incerteza alargada por ele; a de 2,5 s chega depois do prazo de 2 s, a um pedido fechado: `sem_resposta`, nenhum veredito a mais quando ela chega, e o acordo é das outras duas |
| O relógio atrasado | o RTC uma hora atrás | antes das fontes, o civil é o RTC e o lógico anda com ele; o candidato e o salto de +1 h em rodadas seguidas, de `rtc` a `sincronizado`; o NSF observa o `clock-jump` do relógio, com a gravidade pelo tamanho, sem incidente — a confiança é baixa: é o relógio sendo corrigido — e sem pedido |
| O relógio adiantado | o RTC dois minutos à frente | o civil volta em duas rodadas e o lógico para, `adiantado`; parado, ele congela os carimbos, e a sondagem lenta de um operador vira detecção e incidente, sem contenção; a saída do operador depois dela fica na recomendação, com o motivo — o lógico parado —, e o NSF não pede nada; uns dois minutos depois o lógico volta a andar com o civil, o NSF diz a contenção por taxa ativa de novo, e a saída para outro destino continua recomendação, porque a janela que a sustenta foi contada parada; e a contenção por taxa volta: a sondagem nova de outro operador, contada andando, sustenta a da saída seguinte dele — o NSF pede o `net.block` pelo gate, o gate permite, e a conexão seguinte é barrada —; nenhum carimbo da auditoria desce |
| Um dia adiantado | o RTC um dia à frente | o civil volta um dia; o lógico fica no piso, parado; o NSF vê `adiantado`, abre o incidente `logical-clock-stopped` do relógio, sem ação, e diz a contenção por taxa suspensa; a validade é a do civil, autenticado, e não a do lógico um dia à frente: o `Max-Age` vence; e, parado, a contenção que não depende de janela vale: o operador da porta 1 roda um código adulterado (`CODE_TAMPERED`) e depois usa a rede, e o NSF pede o `net.block` do destino pelo gate, que permite — a conexão seguinte do operador é barrada, e o lógico continua parado |
| O piso de outro boot | um boot com o RTC uma hora à frente; o seguinte na hora | o civil do segundo boot sincroniza — a hora do hospedeiro dentro da incerteza —, e o lógico fica no piso do primeiro, parado; a validade é a do civil, autenticado, e não a do piso: o `Max-Age` vence com o civil andando |
| O RTC além dos certificados | o RTC em 2041, depois de `bancada.duke` vencer; as fontes caladas, depois honestas | sem hora autenticada, a validade é a do lógico, em 2041: os dois certificados `TLS_EXPIRED`, o `Expires` de 2023 vencido, o `Max-Age` vencendo; sincronizado, o civil volta quinze anos e o lógico fica parado em 2041, `adiantado`: a validade é a do civil — `bancada.duke` aceito, `vencido.duke` ainda vencido —, e o NSF diz a contenção por taxa suspensa |
| O RTC atrás do piso | um boot na hora, sem fontes, deixa o piso; o seguinte sobe com o RTC em 2020, dentro da validade de `vencido.duke`, e sem fontes; depois, as fontes | o civil é o RTC, não autenticado, e a validade é a do piso: `bancada.duke` aceito, `vencido.duke` `TLS_EXPIRED`, o `Expires` de 2023 vencido — pelo RTC cru, os dois voltariam a valer —; parado, o lógico não vence o `Max-Age`; o NSF vê o lógico parado nas rodadas perdidas, e a contenção por taxa suspensa; com as fontes, o civil sincroniza seis anos à frente, passa do piso, e o lógico anda com ele: a validade é a do civil, e o NSF vê o lógico andando, a contenção por taxa ativa |
| Dez minutos | as três pulam dez minutos à frente | o candidato e o salto em rodadas seguidas, além do envelope; o lógico salta junto; o NSF abre o incidente `clock-jump-beyond-envelope` do relógio, sem ação nem pedido |
| Os pendentes | as três voltam dez minutos; depois pulam dois dias | o salto para trás fora do envelope fica pendente, sem mover o civil, e sai quando elas voltam; o de dois dias fica pendente — a validade segue o civil de agora, autenticado, e não o salto; o NSF recomenda a uma pessoa o `time.confirm` da rodada dele, e não pede nada —; `time.confirm` como comando não existe, a prova com a rodada de outro pendente é `CONFLICT`, gravado com a rodada pedida e a do pendente, e a com a rodada dele aplica o salto; nenhum serviço confirma salto |
| A perda e a volta | a terceira calada desde o boot; depois a segunda; depois a primeira; e as três de volta, cinco segundos à frente | acordo 2/2; sem quórum; a rodada perdida; depois de uma falha, a rodada seguinte em 64 s; a incerteza cresce pela deriva; o NSF conta as respostas que não vieram; a volta é gradual, sem salto, dentro do teto de 5% |
| O firewall | `net.block` numa fonte, depois noutra | o gate permite o `net.connect` do serviço, e o firewall o barra na execução (`DENY_POLICY`, com a regra); nenhum pedido chega às barradas; acordo 2/2, depois sem quórum; tiradas as regras, 3/3 |
| A revogação | `policy.write` tirando `time.sync` do papel `tempo` no meio de uma rodada lenta | o passo de hora seguinte do serviço ouve `DENY_PERMISSION`; a rodada acaba ali, sem fechamento e sem mover nada, e a fonte seguinte não é pedida; com a linha de volta, 3/3 |
| A hora vence | uma imagem com o teto da incerteza baixado a 10 s; o RTC uma hora atrás; raios de 9 e 10 s | o salto traz a incerteza de 9 s; as fontes calam, a incerteza cresce pela deriva, passa do teto, e a hora vence; o lógico segue o civil; o NSF vê `vencido` e abre o incidente `time-unauthenticated` do relógio, sem ação nem pedido; a validade é a do lógico, não autenticada; as fontes voltam, com raio de 1 s: `sincronizado` de novo, a validade pelo civil, e o NSF vê a volta |
| O holdover | sincronizar e calar as três | `sincronizado` pela janela de 2048 s — contada na hora do hospedeiro, que o contador do civil acompanha; o relógio do kernel, no emulador, perde tiques —, uma rodada perdida a cada 64 s, e `holdover` depois dela, abaixo do teto: a validade ainda é a do civil, autenticado; as fontes voltam três segundos à frente: o ajuste gradual, `sincronizado` de novo, a validade pelo civil, e o NSF vê a volta |

Cada cenário também confere, a cada leitura, que o lógico nunca volta. No
fim, a bancada imprime o que mediu: a primeira sincronização depois do
endereço do DHCP, a conferência das respostas, o RTT de cada uma, o tempo
do servidor, e a rodada pelo relógio do kernel e pelo do hospedeiro. O
trabalho `tempo` da CI roda os dezoito cenários nas duas arquiteturas,
em release. Os cenários que conferem a validade rodam o programa
`validade` pela serial, como a fumaça roda o `cifrado`, e leem do log o
que ele disse.

**O que ela achou: o intervalo depois de uma falha.** Dentro da janela, a
hora continua `sincronizado` sem acordo nenhum, e o serviço tomava a
rodada sem acordo — com uma fonte só, ou com nenhuma — por uma que deu
certo: dobrava o intervalo. Com as fontes caladas, eram 1024 s em cinco
rodadas, e a volta delas só era vista até 17 minutos depois. A bancada
pegou isso no cenário da perda: depois da rodada sem quórum, a seguinte
não veio em 104 s. O desenho diz que uma falha volta a 64 s. A regra agora
é uma função pura do desfecho, de já ter sincronizado e do intervalo
anterior, e um caso da suíte confere a tabela dela; a mutação que devolve
a regra antiga reprova o caso. E o kernel passou a medir a rodada:
`round_ns`, do primeiro pedido ao desfecho, e `round_wait_ns`, o que dela
foi espera pelas fontes, no `system.info time`.

### O custo

Medido no hospedeiro, na mesma máquina, antes e depois deste passo —
mediana de sete rodadas, em três execuções: a decisão não mudou, de 7 a
250 ns conforme o pedido, dentro do ruído entre execuções; ler a política
padrão, 16% mais longa e com um papel a mais, passou de 34–36 µs a
38–42 µs; validar uma linha de `policy.write`, de 7 µs a 10 µs. Ler o
registro de três fontes custa 15 µs — quase tudo nas três chaves
conferidas na curva —, uma vez por boot; a coerência com a política, menos
de 1 µs. O registro ocupa 880 bytes.

E o deste passo, medido na mesma máquina e na mesma configuração (x86,
release) — a base do passo anterior e este, alternando, duas vezes cada.
Na fumaça, com perto de 4 700 decisões, o gate de ponta a ponta ficou
igual — 422 a 457 µs antes, 435 a 443 µs depois —, e o registro da
auditoria ficou mais barato — 149 a 180 µs antes, 115 a 154 µs depois: o
tempo lógico deixou de ler o CMOS a cada registro. A média da política
passou de 19–20 µs a 23 µs; a fumaça deste passo tem umas 210 decisões a
mais, as das sondas do tempo e do serviço, e a mistura mudou — o caminho
da decisão não mudou. As cargas de rede da suíte — uma visita HTTP e
quatro ao mesmo tempo, 5 MiB pelo plano de dados, a compressão, os
cookies e o HTTP/2, sozinhos e três ao mesmo tempo — ficaram dentro do
ruído entre execuções, de uns 5%. O `system.info` ficou maior: leva o
objeto `time`.

O que o tempo custa por conta própria: a régua do x86 mede o TSC no boot
por um décimo de segundo — mais, se a primeira medida passar de 200 ppm —;
uma rodada honesta de três fontes, pelo gate, leva de 80 a 120 ms em
release nas suítes inteiras, nas duas arquiteturas (de 170 a 260 ms na
depuração); a conferência de uma resposta — as duas assinaturas Ed25519,
o Merkle e o encadeamento —, de 3 a 9 ms em média, em release, e é só
conta: o que varia entre as execuções é a máquina; a rodada inteira num
fio, 18–19 KiB da pilha em release e 41–42 KiB na depuração, dos 60 KiB.
E o fio do serviço não custa nada parado: bloqueado, não ocupa núcleo
nenhum entre as rodadas.

E pela rede de verdade, na bancada de tempo — release, emulado; as
bancadas inteiras deste passo, uma arquitetura de cada vez, numa máquina
de quatro núcleos, e as da CI. A primeira sincronização chega de 80 a
300 ms depois do endereço do DHCP, na primeira rodada do serviço; a
exceção está logo abaixo. Uma rodada das fontes honestas leva de 60 a
100 ms no relógio do kernel, mais da metade esperando as fontes; o kernel
gasta nela de 20 a 42 ms, em média — as dezoito operações pelo gate, seis
por fonte, com a auditoria delas, que vai ao journal, e as três
conferências —, e a primeira do boot é a mais cara. A rodada com as três
caladas, sem conferência nenhuma, gasta de 6 a 11 ms. A conferência de uma
resposta leva de 3,2 a 4,1 ms em média, e a maior, até 11 ms; no
hospedeiro, nativo, de 107 a 123 µs, e de 9 a 10 µs quando a delegação é
recusada antes das contas da curva: as duas Ed25519 são quase tudo, e o
emulador as faz umas trinta vezes mais devagar. O RTT de uma resposta
aceita é de 18 a 20 ms na mediana — dos quais de 9 a 11 ms são do
servidor, que assina num `xtask` de depuração. Uma rodada grava 25
registros do serviço na auditoria.

### Os consumidores da hora

Quem confere uma validade lê a hora do objeto `time` do `system.info`,
pelo gate, como qualquer pedido do programa: o TLS, a dos certificados; o
pote de cookies, o `Expires` e o `Max-Age`. Os dois leem pela mesma regra,
num lugar só — `protocolo::usuario::hora` —, e nenhum tem regra própria (o
desenho, §10 e a decisão D3):

| O estado | A hora da validade | Por quê |
|---|---|---|
| `sincronizado`, `holdover` | o **civil** | a hora autenticada: as fontes concordaram, e a incerteza cabe no teto. O lógico parado à frente dela (`adiantado`) é que mentiria: um certificado que vale não vence por ele |
| `rtc`, `vencido` | o **tempo lógico**: o civil com o piso do journal | sem hora autenticada, o civil é o RTC, ou uma hora que a incerteza já não sustenta; o piso, que nunca volta, não deixa um RTC atrasado de propósito ressuscitar o certificado nem o cookie que venceram |
| `desligado` | o tempo lógico | sem civil; e sem lógico — sem RTC e sem piso — falta relógio: a conexão é recusada (`CLOCK_UNAVAILABLE`), e o cookie com validade não vai |

O RTC cru nunca vale como prova. As marcas não mudam a regra, e vão na
saída: com um salto `pendente`, o civil não se moveu, e a validade segue o
civil de agora — nunca o salto que ninguém confirmou —; com uma fonte
`divergente`, o civil é o das que concordaram; com o lógico `adiantado`,
vale o civil se a hora é autenticada, e o lógico — o piso — se não é, e
nunca o RTC atrás dele. Sem hora autenticada, o TLS conecta como antes,
pelo lógico, e diz o estado (D3): recusar (`CLOCK_UNTRUSTED`) é de uma
política temporal, quando ela existir.

**O programa diz com que hora conferiu.** O `cifrado` diz, antes do
aperto, `a validade pela hora sincronizado, autenticada, +-986 ms`, ou
`rtc, nao autenticada: a do tempo logico`, com as marcas — `salto
pendente`, `uma fonte divergente`, `o logico adiantado`. O programa
`validade` diz a hora, os segundos com que conferiu, os do civil e os do
lógico, e o que ela deu no eco TLS — `bancada.duke`, válido de 2025 a
2040, `vencido.duke`, de 2020 a 2021, e `futuro.duke`, de 2042 a 2044,
que nenhum estado aceita (`TLS_NOT_YET_VALID`) — e nos cookies — um `Expires` de
2023, um de 2100 e um `Max-Age=10`: os que o pote levou logo depois de
guardar, e os que levou 12 s depois. O programa não julga: a bancada sabe
o que cada estado deve dar.

**A hora confere a validade, e mais nada.** O cookie não é identidade,
credencial, autoridade nem permissão; o certificado prova o nome ao
programa, e não autoriza nada no gate; e o estado do relógio não concede
nem nega nada — o gate decide pelo relógio do kernel, e nenhuma decisão de
autorização lê o civil nem o lógico. Os arrendamentos, as sessões, as
taxas e as esperas continuam no monotônico; os prazos das mensagens e os
carimbos da auditoria, no lógico. A leitura é a mesma de antes — um
`system.info` por conexão TLS, e um por troca HTTP com um cookie com
validade em jogo —, agora do objeto `time` em vez do relógio da
persistência.

**O NSF e o tempo.** As regras de tempo do desenho (§9.3) leem os
registros de `time.sync` e `time.confirm`, nunca um relógio, e cada uma
dispara uma vez por acontecimento — o salto da rodada, a entrada no
estado, a primeira recusa de uma fonte —, e não a cada rodada que o
repete:

| Regra | Dispara com | Gravidade, confiança |
|---|---|---|
| `clock-jump` | o salto que o envelope explica, ou o da primeira sincronização | pelo tamanho — baixa abaixo de 1 min, média até 1 h, alta acima —; confiança baixa: é o relógio sendo corrigido |
| `clock-jump-beyond-envelope` | o salto que a incerteza não explica: o contador derivou, ou as fontes se moveram juntas | alta, média |
| `clock-jump-pending` | o salto que só uma pessoa confirma: recomenda `time.confirm {round}`, com a rodada dele, a quem tem a prova | alta, média |
| `time-source-divergent` | uma fonte fora do acordo, com os vereditos da rodada como evidência | média, média |
| `time-source-bad-signature` | uma resposta que a chave fixada não fecha — forjada, ou a chave foi trocada —, uma vez por fonte até ela ser aceita de novo | alta, média |
| `time-unauthenticated` | a hora vencida; ou três rodadas de um boot sem hora autenticada — esta, uma observação | média, média; média, baixa |
| `logical-clock-stopped` | o lógico parado à frente do civil, uma vez por parada | média, média |

O principal delas é o relógio (`clock`), e não o serviço de hora, que
continua observado e nunca alvo. Elas registram e recomendam: nenhuma
bloqueia uma fonte — quem forja respostas ruins não escolhe o que o NSF
corta —, nenhuma confirma um salto, e nenhuma é da categoria que sustenta
contenção.

**Com o lógico parado, a contenção por taxa fica suspensa.** Parado o
lógico, param os carimbos, e as janelas de 30 s das regras juntam o que no
relógio de verdade está separado. O NSF sabe da parada pelos registros — a
marca `adiantado` no fechamento de uma rodada, ou um `time.confirm` que
deixa o lógico à frente do civil —, e da volta pelo primeiro carimbo
maior. Enquanto parado, as detecções das regras de janela continuam
registradas, marcadas (`com o tempo logico parado: a janela pode juntar o
que no relogio esta separado`), e abrem o incidente como antes; a
contenção que só uma janela sustenta — o `net.block` da saída depois da
sondagem — vira recomendação, com o motivo, e o NSF não pede nada. A
janela contada parada continua sem sustentar contenção depois que o
lógico volta a andar; uma janela contada andando volta a conter. O que não
é janela — o teto do administrador exercido, o código adulterado — contém
parado ou não. O `security.status` diz `logical_stopped`,
`stopped_at_ms` e `rate_containment` (`suspended` ou `active`).

**Onde se confere.** No hospedeiro, a regra da hora em cada estado e cada
marca (`protocolo`), e as regras de tempo, a suspensão, a volta e o
contorno que contém parado (`seguranca`). Na suíte, dois casos: `hora: a
validade dos programas pela regra deles, em cada estado` — o
`system.info time` lido pela regra em `rtc`, `sincronizado`, `holdover`,
`vencido` e de volta —, e `tls: a validade pela hora autenticada, com
rodadas e o NSF ao mesmo tempo` — três programas `validade` de uma pessoa,
com rodadas e o NSF lendo ao mesmo tempo, cada um conferindo pelo civil. E
na bancada de tempo, cada estado com o programa
de verdade, pela rede de verdade (ver os cenários acima): a hora vencida,
o holdover e a volta, o pendente, a fonte divergente, o piso de outro
boot, o RTC além dos certificados e o RTC atrás do piso. As sete regras de
tempo, cada uma pelo nome, na imagem de produção: `clock-jump` no relógio
atrasado — uma observação —, `clock-jump-beyond-envelope` nos dez minutos,
`clock-jump-pending` nos pendentes, `time-source-divergent` na fonte
divergente, `time-source-bad-signature` na forjada, `time-unauthenticated`
na hora que vence e `logical-clock-stopped` no dia adiantado — e nenhuma
com ação, a não ser a recomendação do pendente a uma pessoa.

### O que fica de fora

- **Um servidor só, do mesmo autor.** O servidor da bancada é escrito à
  parte do pacote `hora`, mas da mesma leitura da RFC: ele confirma o
  caminho — a placa, o emulador, o firewall, o gate, a conferência, o
  quórum e a disciplina —, e não a leitura do formato. Um erro de leitura
  que estivesse dos dois lados passaria pelos dois; contra isso, só o
  vetor da RFC 10049, que os testes do servidor e os do `hora` conferem.
  Nenhum servidor de outro autor respondeu à máquina: os públicos a bancada
  não alcança, e nenhum de terceiros roda aqui.
- **A primeira rodada pode sair antes do endereço.** O serviço começa
  logo depois da pilha de rede, e nada espera o DHCP. Em duas execuções da
  CI do ARM, uma e três máquinas de seis sincronizaram na segunda rodada,
  até 4 s depois do endereço, e não na primeira, uns 0,1 s depois. Nada
  errado é aplicado — a rodada sem acordo fica registrada, e a seguinte
  vem 2 s depois, como o desenho manda até sincronizar —; esperar o
  endereço antes da primeira rodada fica como proposta.
- **A fumaça principal roda sem servidor.** A fumaça e a bancada de
  persistência rodam a imagem de produção sem fontes: o serviço faz as
  rodadas, nenhuma resposta chega, e o civil fica no RTC. Os servidores da
  suíte moram no kernel de teste (`rede::bancada_hora`), depois do firewall
  e antes da placa; o recurso que os liga só existe no kernel da suíte, e o
  `xtask` confere que nenhum outro manifesto o pede. Na fumaça principal, o
  TLS confere pelo tempo lógico, e o `cifrado` diz `rtc, nao autenticada`.
  O acordo de verdade, na imagem de produção, é o do boot da hora
  autenticada da fumaça — com o servidor da bancada de tempo no
  hospedeiro —, e o da bancada de tempo; a fumaça com teclado USB e a com
  virtio-gpu não repetem esse boot.
- **O NSF só sabe do lógico parado por uma rodada.** A parada se lê da
  marca `adiantado` no fechamento de uma rodada, ou de uma confirmação que
  deixa o lógico à frente do civil. Sem fontes no registro, ou antes da
  primeira rodada de um boot que sobe com o RTC atrás do piso, nenhum
  registro diz que o lógico está parado: as janelas juntam o que no
  relógio está separado, e a contenção por taxa não fica suspensa. A
  primeira rodada sai logo depois da pilha de rede.
- **Parado, o lógico não vence nada.** Sem hora autenticada, a validade é
  a do lógico; com ele parado no piso — o RTC atrás dele —, um `Max-Age`
  não vence, como não vence um prazo de mensagem, até o civil passar o
  piso ou a hora ser autenticada. O certificado vencido continua vencido:
  parado, o lógico não volta. Um salto confirmado para a frente envelhece
  de uma vez os prazos das mensagens.
- **A recomendação do `time.confirm` nomeia a rodada dela.** O NSF
  recomenda confirmar o salto pendente pela rodada que o pediu; se outra
  rodada troca o pendente antes da confirmação, a recomendada é um
  `CONFLICT`, gravado, e nada se move — quem confirma lê o
  `pending_round` de novo. O NSF não confirma: não tem prova.
- **O número da rodada vale no boot.** As rodadas são numeradas a partir
  de 1 a cada boot, e o salto pendente não sobrevive a um reboot. Um
  número lido antes de um reboot pode coincidir com o de um pendente novo
  depois dele: confirmar com ele é confirmar o pendente de agora, que o
  administrador não leu. Quem confirma lê o `pending_round` no boot em que
  confirma — o desafio de `admin.execute` também é do boot e da sessão.
- **A folga da pilha.** No perfil de depuração, a rodada inteira usa
  68% (x86) a 70% (ARM) da pilha de um fio; no de produção, bem menos. O
  caso da suíte exige folga de um quarto. O que a pilha de um fio tem de
  mais fundo hoje é a da rede, sob `net.recv`; um caminho mais fundo que
  passe a rodar no fio do serviço pede a conta de novo.
- **A régua do x86 nos tiques.** A calibração do TSC é uma medida no boot.
  Num hospedeiro muito carregado, as cinco tentativas podem passar de
  200 ppm, e a régua cai para os tiques, com 5% de deriva: o civil vence o
  teto da incerteza minutos depois de cada acordo, e o `system.info` diz
  `ticks`. Não há segunda medida depois do boot. A frequência também não é
  aprendida das amostras: com raios de segundos, separar 100 ppm pediria
  dias entre rodadas.
- **Bloquear uma fonte não tira a confiança nela.** O firewall corta o
  caminho do serviço até uma fonte; a resposta dela, chegada por outro
  caminho permitido e entregue por quem tem `time.sync`, ainda vale — a
  confiança é o registro, e tirar uma fonte é uma imagem nova.
- **A taxa do `tempo`.** Uma rodada honesta são seis operações por fonte
  — pedido, conexão, envio, leitura, entrega e fecho —, dezoito para as
  três, mais uma decisão por leitura que espera, refeita ao acordar: perto
  da rajada de `taxa tempo 10 20`, com a reposição de dez por segundo
  durante a rodada e o intervalo entre rodadas enchendo o balde de novo.
  As rodadas da suíte, ao lado das do sistema, cabem nela. Com respostas
  recusadas, cada fonte pode gastar até quatro leituras e quatro entregas,
  e a rodada pode esbarrar na taxa: ela acaba, e a recusa fica gravada.
  Quem consegue injetar lixo no caminho já consegue calar as fontes.
- **A coerência do boot só avisa**, e **o registro em tempo de execução**
  não existe: os dois continuam como no passo anterior. Os tetos do
  desenho — o prazo de 2 s, o raio de 10 s, a janela de 2048 s — não foram
  medidos contra servidores públicos, que esta bancada não alcança.

### As mutações da superfície

Cinquenta e duas mutações contra o que a superfície do tempo promete — que
`time.sync` não vire autorização implícita, que `time.confirm` não chegue
ao operador nem saia da operação administrativa, que o `sistema` não seja
curinga, que o registro recuse o que deve e que a imagem não saia
incoerente —: trinta e seis contra os testes da `politica`, do `hora` e do
`xtask` e contra as invariantes, no hospedeiro; dezesseis contra as
invariantes e os casos `tempo:` da suíte, no x86. **Cinquenta e uma
reprovadas**; a que sobreviveu é equivalente. Três das do kernel morreram
só nas invariantes, e duas ganharam uma variante que escapa da invariante
— sem nomear a permissão, lendo o anexo sem conferi-lo —, para saber se a
suíte também as pega: pega.

| Mutação | Reprovada por |
|---|---|
| a permissão `time.sync` não sensível: atravessaria a inclusão | `as_do_tempo`, `as_do_tempo_nao_atravessam_a_inclusao`, `o_tempo_nao_herda_o_sistema` |
| `decidir` deixa `time.sync` a qualquer papel | `a_matriz_aprovada`, `o_tempo_nao_herda_o_sistema`, `policy_write_e_o_tempo` e mais dois; no registro, `a_coerencia_segue_a_politica_de_agora` e `um_papel_que_nao_conecta` |
| o operador da imagem com `time.sync` | `a_matriz_aprovada`, `as_do_tempo_nao_atravessam_a_inclusao`, `o_tempo_da_imagem_e_coerente` e as invariantes |
| a inclusão leva as sensíveis | `sensivel_nao_atravessa_a_inclusao`, `as_do_tempo_nao_atravessam_a_inclusao`, `o_tempo_nao_herda_o_sistema` e mais três |
| o comando `time.request` exige `system.read` | `tempo: o servico pede pelo gate`, `tempo: o servico nao e o sistema` |
| o comando `time.sync` exige `system.read` | `tempo: o servico pede pelo gate`, `tempo: nenhum caminho cria autoridade` |
| o operador da imagem com `time.confirm` | `a_matriz_aprovada`, `o_sistema_e_maximo_e_enumerado`, `o_tempo_da_imagem_e_coerente` e mais um, e as invariantes |
| a permissão `time.confirm` não administrativa | `as_do_tempo`, `o_sistema_e_maximo_e_enumerado`, `o_tempo_da_imagem_e_coerente` e as invariantes |
| a operação `time.confirm` exige `time.sync` | as invariantes: `Permissao::TimeSync` fora dos comandos |
| a mesma, sem nomear `time.sync` | `tempo: confirmar so com prova` — a decisão não foi gravada com `time.confirm` |
| a operação `time.confirm` aceita uma hora | `tempo: confirmar so com prova` — a hora digitada não foi recusada |
| a operação `time.confirm` diz que confirmou | o mesmo caso — sem salto pendente, fez alguma coisa |
| um comando comum exige `time.confirm` | as invariantes: `Permissao::TimeConfirm` fora da operação administrativa |
| `decidir`: o `sistema` pode tudo | `a_matriz_aprovada`, `o_fs_write_do_sistema_e_so_a_linha`, `caminho_sem_alcance_nao_e_tudo_na_decisao` e mais dois |
| o serviço com o papel do sistema aceito | `o_servico_nao_herda_o_sistema`, `o_tempo_nao_herda_o_sistema` |
| o serviço decide pelo papel local, o do sistema | `tempo: o servico pede pelo gate`, `tempo: o servico nao e o sistema` |
| sem a linha `servico`, o papel local | `tempo: o servico nao e o sistema` — sem a linha, decidiu por algum papel |
| o `tempo` da imagem inclui o `sistema` | `o_tempo_nao_herda_o_sistema`, `o_servico_de_hora_decide_pelo_papel_tempo`, `o_tempo_da_imagem_e_coerente` e mais dois, e as invariantes |
| quórum de uma chave; quórum sem mínimo | `quorum_abaixo_de_dois_e_recusado` |
| quórum sem máximo | `quorum_maior_que_as_fontes_so_confere` |
| k acima das fontes move o relógio | o mesmo teste e `o_tempo_da_imagem_e_coerente` |
| a chave de ordem pequena; o hexadecimal maiúsculo | `chaves_invalidas` |
| o destino TCP | `destinos` |
| **o destino fora da forma normal** | **sobreviveu** — equivalente: o `endereco::ler` da política só lê a forma normal, e a conferência do registro repete a dele |
| o nome, o destino ou a chave repetidos (três) | `repetidos` |
| sem fontes | `a_forma_das_linhas` |
| sem quórum | `sem_quorum_e_recusado` |
| os tetos de `salto` e de `incerteza` — o teto exclusivo, sem teto, abaixo do raio (quatro) | `os_tetos_nos_limites` (e `o_registro_da_bancada`) |
| os parâmetros sem o teto do salto | `os_tetos_nos_limites` |
| a coerência sem `time.sync` | `a_coerencia_segue_a_politica_de_agora`, `um_papel_que_nao_conecta` |
| a coerência pelo `net.send` | `coerente_com_a_padrao`, `fonte_sem_destino_na_politica`, `o_tempo_da_imagem_e_coerente` e mais um |
| a coerência ignora os destinos | `fonte_sem_destino_na_politica`, `a_coerencia_segue_a_politica_de_agora`, `o_tempo_da_imagem_e_coerente` |
| um balde para todos os serviços | `tempo: cada servico tem o seu balde` — o de hora gastou a ficha do NSF |
| o serviço sem balde próprio | o mesmo caso e `tempo: o servico nao e o sistema` |
| o comando `time.request` sem conferir o registro | `tempo: o servico pede pelo gate` — uma fonte fora do registro existiu |
| o comando `time.sync` sem conferir o anexo | as invariantes: `attachment` declarado e nunca lido |
| a mesma, lendo o `attachment` | `tempo: nenhum caminho cria autoridade` — o anexo que não confere foi aceito |
| o boot sem o registro | `tempo: o registro do boot`, `tempo: o servico pede pelo gate` |
| o registro dá a primeira fonte a qualquer nome | `tempo: o servico pede pelo gate` |
| a imagem sem a coerência, com k acima das fontes, com destino a mais no `tempo`, com `time.sync` em qualquer papel, com `time.confirm` fora do administrador (cinco) | `o_tempo_da_imagem_e_coerente` |
| a lista das chamadas protegidas deixa `time.confirm` nos comandos | as invariantes — acusam a lista que não confere nada |

### As mutações do relógio e do serviço

Cinquenta mutações contra o que o relógio e o serviço prometem — que
uma fonte só não mova a hora, que nenhuma resposta valha sem o pedido dela
e as duas assinaturas, que nada mova o civil fora dos dois tratadores, que
o lógico não volte nem se misture ao monotônico, que o NSF não ajuste nada,
que a auditoria não perca uma rodada, que a concorrência não corrompa uma e
que o serviço espere sem tirar o sono dos núcleos —: duas contra os testes
do hospedeiro e as invariantes, treze nas duas camadas — o hospedeiro e os
casos `tempo:` e `hora:` da suíte, no x86 — e trinta e cinco contra as
invariantes e a suíte. **Todas reprovadas** — uma delas só pela fumaça do
ARM, porque o fio do serviço não roda na suíte. Na primeira passada, três
sobreviveram, e cada uma mudou alguma coisa: o ponto de commit sem conferir
a versão da política e sem refazer a decisão pediram o caso do ponto de
commit, que põe a mudança no meio da conferência da última resposta; e o
pedido substituído deixado aberto era equivalente — a tabela do pacote já o
substitui —: o código redundante saiu, e a mutação foi para o lugar certo.
Seis morreram só nas invariantes; as quatro que importam ganharam variantes
que escapam delas — o NSF confirmando por um ponteiro de função, o gate
lendo o civil por um ajudante e sem nomear a permissão, a espera da rede e
a do serviço descansando sem nomear a função —: a suíte pega três, e a
fumaça do ARM a do serviço, que só a imagem de produção roda. A
quinquagésima é o código de antes da correção que o CI pediu —
`bloquear_em` saindo sem voltar a rodar —, e o caso novo do escalonador a
reprova na primeira volta, nas duas arquiteturas.

| Mutação | Reprovada por |
|---|---|
| o quórum aceita k = 1 — no pacote; e com o kernel pedindo k = 1 | `k_menor_que_dois_nunca_da_acordo`; `hora: k dois sempre` e `hora: fontes divergentes` — uma fonte sozinha moveu o relógio |
| uma fonte sozinha vira quórum, com a amostra duplicada noutra chave | `hora: k dois sempre` |
| o quórum com k − 1 fontes | `uma_fonte_so_nunca_move_o_relogio` e mais cinco; `hora: k dois sempre` |
| ignorar o nonce | `nonce` e mais dois; `hora: cada resposta ruim e um veredito` |
| ignorar a assinatura da resposta; a da delegação | `assinatura_da_resposta` e mais três; `assinatura_da_delegacao` e mais cinco; `hora: cada resposta ruim e um veredito` |
| ignorar o Merkle | `outro_pedido`, `o_vetor_da_rfc_10049_e_aceito` e mais quatro; `hora: cada resposta ruim e um veredito` |
| ignorar a janela da delegação; sem teto do raio | `fora_da_delegacao`; `raio`; e o mesmo caso |
| o id não se consome na aceita — o nonce repetido | `a_resposta_valida_da_a_amostra_e_consome_o_id`; `hora: rodadas, leitores e o NSF ao mesmo tempo` — sobraram pedidos abertos |
| a entrega sem pedido mexe na fonte em curso | `tempo: o servico pede pelo gate` — uma entrega sem pedido aberto foi aceita |
| a entrega acha o pedido de outro principal — o nonce estrangeiro | `hora: entregas fora do pedido` |
| o nonce sem encadear; a fonte seguinte com a anterior aberta; a resposta aceita trocada por um pedido novo | `hora: os nonces encadeados e a ordem da rodada` |
| o pedido substituído fica aberto na tabela | `um_pedido_novo_para_a_mesma_fonte_substitui` e mais um; `hora: os nonces encadeados e a ordem da rodada` |
| **a rodada aplicada sem conferir a versão da política** | **sobreviveu à primeira passada**; `hora: o ponto de commit da rodada` — a escrita de política no meio da conferência |
| a mesma, e a entrega sem largar as rodadas de outra política | `hora: revogacao e politica no meio da rodada`, `hora: o ponto de commit da rodada` |
| **o commit sem refazer a decisão** | **sobreviveu à primeira passada**; `hora: o ponto de commit da rodada` — a sessão da pessoa que acabou |
| sem teto de taxa no ajuste gradual | `o_ajuste_gradual_para_a_frente_tem_teto_de_taxa` e mais dois; `hora: a disciplina no civil` — o ajuste aplicou o desvio de uma vez |
| o salto para trás sem confirmação; acima do teto sem confirmação; numa rodada só | os da disciplina no hospedeiro, de três a oito cada; `hora: a disciplina no civil` |
| o `time.confirm` aceita parâmetros; põe a hora digitada no civil | `tempo: confirmar so com prova` — a hora digitada não foi recusada |
| o `time.confirm` sem salto pendente diz que confirmou | `tempo: confirmar so com prova`, `hora: a disciplina no civil`, `hora: nenhum caminho fora do gate` |
| o tratador fora de um comando age como o sistema | `hora: nenhum caminho fora do gate` |
| `time.sync` decidido por `system.read` | `tempo: o servico pede pelo gate`, `tempo: nenhum caminho cria autoridade` e mais onze |
| o NSF confirma o salto pendente | as invariantes: `hora::confirmar(` fora da operação administrativa |
| a mesma, por um ponteiro de função | `hora: a disciplina no civil` — o salto acima do teto não ficou pendente |
| o gate lê o civil | as invariantes: o ponto de decisão lê o relógio civil |
| o gate deixa `time.sync` a todos fora de sincronizado, por um ajudante | as invariantes: `Permissao::TimeSync` fora dos comandos |
| a mesma, sem nomear a permissão | `tempo: pessoa e agente pela mesma politica`, `tempo: o servico nao e o sistema` |
| o lógico sem o piso | `hora: a disciplina no civil` — o lógico voltou com o civil |
| o lógico pelo monotônico | `hora: a regua e os tres relogios`, `hora: a disciplina no civil` |
| o salto move o monotônico | `hora: a disciplina no civil` — o salto moveu o monotônico |
| a rodada fecha sem registro; o veredito sem registro | `hora: uma rodada honesta pelo gate` e mais oito; e mais três |
| o serviço de hora no balde do NSF | `tempo: cada servico tem o seu balde` |
| a vez da hora sem trava | `hora: rodadas, leitores e o NSF ao mesmo tempo` — o kernel cai com a rodada corrompida |
| as rodadas de principais diferentes se misturam | `hora: entregas fora do pedido`, `hora: rodadas, leitores e o NSF ao mesmo tempo` |
| a invariante deixa outro arquivo mover o civil | as invariantes — acusam a lista que não confere nada |
| o aviso que chega antes do sono se perde (`bloquear_em` sem a marca) | `fios: quem bloqueia sai do rodizio` — o fio dormiu para sempre |
| `bloquear_em` descansa em vez de bloquear | `fios: quem bloqueia sai do rodizio`, `hora: a resposta atrasada na rede` — o fio nunca saiu do rodízio |
| `bloquear_em` sai sem voltar a rodar — o código de antes | `fios: quem volta do bloqueio volta rodando` — o fio da suíte voltou esperando na primeira volta, no x86 e no ARM |
| o serviço descansa entre as rodadas | as invariantes: `descansar_ate_a_interrupcao()` fora da lista |
| a mesma, sem nomear a função | a fumaça do ARM: a sonda da tela — cada `video.sample` de novo duas vezes mais lento |
| a espera da rede descansa | as invariantes |
| a mesma, sem nomear a função | `hora: a resposta atrasada na rede` — a rodada esperou sem sair do rodízio |

A finalização — `time.confirm { round }` — teve dez mutações próprias, cada
uma contra os casos `tempo:` e `hora:` da suíte, no x86: as cinco do pedido
— tirar a comparação da rodada, aceitar qualquer rodada, ignorar a rodada,
confirmar o pendente mais recente qualquer que seja a rodada e confirmar
sem pendente — e cinco no contrato e na evidência. **Todas reprovadas**, e
as do pedido por mais de um caso.

| Mutação | Reprovada por |
|---|---|
| sem a comparação da rodada | `hora: a confirmacao nomeia a rodada` — a confirmação de A, com o pendente de B, não foi um conflito; `hora: confirmacao e rodada nova ao mesmo tempo` — uma rodada que já não era a do pendente foi confirmada |
| qualquer rodada aceita: a de outra, trocada pela do pendente | os mesmos dois |
| a rodada ignorada: a do pendente no lugar da pedida | os mesmos dois |
| o pendente mais recente, qualquer que seja a rodada (`>=`) | os mesmos dois |
| a confirmação sem pendente | `tempo: confirmar so com prova`, `hora: a disciplina no civil`, `hora: a confirmacao nomeia a rodada` e `hora: nenhum caminho fora do gate` |
| outros campos ao lado da rodada | `tempo: confirmar so com prova`; `hora: a confirmacao nomeia a rodada` — com o pendente esperando, o pedido que não é só a rodada passou |
| sem a rodada, a do pendente | os mesmos dois |
| a rodada como texto | os mesmos dois |
| o conflito do `time.confirm` sem registro | `tempo: confirmar so com prova`, `hora: a confirmacao nomeia a rodada` — a decisão sem o conflito depois dela —, `hora: confirmacao e rodada nova ao mesmo tempo` |
| a rodada nova troca o salto e deixa o número da anterior | `hora: a confirmacao nomeia a rodada` — B não trocou o pendente pelo dela; `hora: confirmacao e rodada nova ao mesmo tempo` |

### As mutações dos consumidores

Dezoito mutações contra o que os consumidores e o NSF prometem — que a
validade não seja a do lógico com a hora autenticada, nem a do RTC cru sem
ela; que o TLS e os cookies não deixem de conferir a validade; que o NSF
dê as regras de tempo, suspenda a contenção por taxa com o lógico parado,
e só ela, e não corte fonte nenhuma —, em três camadas: os testes do
hospedeiro e as invariantes; os casos da suíte, no x86; e a bancada de
tempo, no x86, em release, com o programa `validade` de verdade pela rede
de verdade. **Todas reprovadas**, e as que tiram a verificação temporal ou
usam o RTC cru, pela bancada. Quatro delas — as que mexem no TLS e nos
cookies dos programas, que não têm testes no hospedeiro — só a bancada
pode reprovar, e reprova. Na primeira passada, quatro sobreviveram ao caso
da validade da suíte, que tirava o esperado de cada estado da própria
regra conferida — o RTC tratado como autenticado, a hora vencida tratada
como autenticada, a regra só pelo lógico e só pelo civil —, e com o civil
igual ao lógico, as duas horas não se separavam: o caso agora escreve o
esperado de cada estado, e confere também com o lógico parado 25 s à
frente do civil, autenticada e vencida. E a mutação do RTC autenticado
caía antes da hora, no leitor do `system.info` — que recusa um estado
autenticado sem incerteza, e o programa ficava sem relógio —: uma variante
sem essa conferência mostra que a bancada a reprova pelo que importa, o
certificado vencido aceito.

| Mutação | Hospedeiro e invariantes | Suíte | Bancada de tempo |
|---|---|---|---|
| o TLS confere pelo lógico, com a hora autenticada | — | — | o RTC além dos certificados: sincronizado, `bancada.duke` dá `TLS_EXPIRED` pelo lógico parado em 2041 |
| o TLS confere pelo RTC cru | — | — (na suíte o civil e o RTC andam juntos) | o RTC atrás do piso: `vencido.duke` aceito e `bancada.duke` `TLS_NOT_YET_VALID`, pelo RTC de 2020 |
| a regra trata o `rtc` como autenticado | `os_nomes_vao_e_voltam`, `sem_hora_autenticada_e_a_do_logico` | `hora: a validade dos programas…` — o leitor recusa | o RTC atrás do piso: o programa fica sem relógio (`CLOCK_UNAVAILABLE`) |
| a mesma, sem a conferência da incerteza | e `o_que_nao_se_entende_e_recusado` | `hora: a validade dos programas…` | o RTC atrás do piso: `vencido.duke` aceito, e o cookie vencido em 2023 volta |
| a regra trata o `vencido` como autenticado | `o_que_o_programa_diz` e mais dois | `hora: a validade dos programas…` | a hora vence: o programa diz `vencido, autenticada` |
| a regra sempre pelo lógico | `a_hora_autenticada_e_a_do_civil` | `hora: a validade dos programas…` | o RTC além dos certificados: `TLS_EXPIRED`, e o `Max-Age` não vence |
| a regra sempre pelo civil | `sem_hora_autenticada_e_a_do_logico` | `hora: a validade dos programas…` | o RTC atrás do piso: `vencido.duke` aceito, e o cookie de 2023 volta |
| os cookies pelo lógico | — | — | o piso de outro boot e o RTC além dos certificados: o `Max-Age` não vence com a hora autenticada |
| os cookies pelo RTC cru | — | — | o RTC atrás do piso: o cookie de 2023 vai no pedido |
| os cookies sem a validade | `a_validade` e mais quatro | `cookies: o programa inteiro pelo gate`, `tls: a validade pela hora autenticada…` | o RTC atrás do piso: o cookie de 2023 vai, e o `Max-Age` nunca vence |
| o TLS sem a validade — um verificador que aceita o vencido e o que ainda não vale | `o_vencido_e_o_que_ainda_nao_vale_sao_recusados` e mais um; as invariantes: um atalho na verificação do TLS | `tls: o programa cifrado conversa pelo gate`, `tls: a validade pela hora autenticada…` | o RTC atrás do piso: `vencido.duke` aceito |
| o NSF sem a suspensão | `com_o_logico_parado_a_contencao_por_taxa_fica_suspensa` | — | o relógio adiantado: com o lógico parado, o NSF pede o `net.block` da saída do operador, e o gate o deixa |
| a janela contada parada esquecida quando o lógico anda | o mesmo | — | o relógio adiantado: andando, a saída para outro destino vira `net.block` |
| o lógico nunca volta a andar, para o NSF | `de_volta_a_andar_a_janela_contem` e mais dois | — | — |
| sem a regra do lógico parado | `as_regras_de_tempo` e mais dois | — | — |
| sem a regra do salto pendente; sem a da assinatura | `as_regras_de_tempo` | — | — |
| uma regra de tempo bloqueia a fonte | `revogar_e_recomendacao` | — | — |

### As mutações do fechamento

Doze mutações contra as propriedades críticas do fechamento do tempo
autenticado — onze propriedades, e o RTC cru de dois jeitos: no kernel, o
lógico sem o piso; nos consumidores, o `rtc` tratado como hora
autenticada —, em três camadas: os testes do hospedeiro e as invariantes;
os casos da suíte, no x86; e a bancada de tempo, no x86, em release, na
imagem de produção, com o programa `validade` de verdade, o servidor
Roughtime da bancada e o NSF lendo a auditoria. **Todas reprovadas, e
todas pela bancada.** As três que mexem no kernel não têm testes no
hospedeiro; a suíte e a bancada as reprovam.

Numa passada, a do NSF sem a suspensão falhou antes do que ela mexe: o
cenário dos dois minutos pedia o salto na rodada logo depois do primeiro
candidato, e veio um candidato a mais. Depois de um candidato, o serviço
marca a rodada seguinte para a separação mínima (4 s) no relógio do
kernel, e a disciplina mede a separação no contador do civil; no emulador
os dois andam a taxas diferentes, e a rodada chegou 3,8 s depois, pelo
contador — cedo demais: candidato de novo, com o primeiro guardado, e o
salto na seguinte. É o desenho — duas rodadas seguidas e separadas, nunca
uma só —, e a bancada pedia mais que ele nos três cenários com o candidato
e o salto. `salto_confirmado` confere a propriedade do desenho, um teste
no hospedeiro a fixa (e reprova tanto a versão estrita de antes quanto uma
frouxa), e a mutação, de novo, foi reprovada pelo que importa.

| Propriedade | Mutação | Hospedeiro e invariantes | Suíte | Bancada de tempo |
|---|---|---|---|---|
| o RTC cru no lugar do piso | o lógico do kernel é o civil de agora, sem o piso | — | `hora: a disciplina no civil` — o lógico voltou com o civil | o RTC atrás do piso: o segundo boot sobe com o lógico no RTC de 2020, abaixo do piso do primeiro |
| o RTC cru nos consumidores | o `rtc` tratado como hora autenticada, sem a conferência da incerteza | `os_nomes_vao_e_voltam`, `o_que_nao_se_entende_e_recusado` e `sem_hora_autenticada_e_a_do_logico` | — | o RTC atrás do piso: a validade pelo RTC de 2020, e não pelo piso |
| o lógico com a hora autenticada | a regra sempre pelo lógico | `a_hora_autenticada_e_a_do_civil` | — | um dia adiantado: a validade pelo lógico, um dia à frente do civil autenticado |
| o civil sem hora autenticada | a regra sempre pelo civil | `sem_hora_autenticada_e_a_do_logico` | — | o RTC atrás do piso: a validade pelo RTC de 2020 |
| o certificado vencido aceito | o verificador aceita o vencido e o que ainda não vale | `o_vencido_e_o_que_ainda_nao_vale_sao_recusados` e mais um; as invariantes: um atalho na verificação do TLS | — | as fontes honestas: `vencido.duke` e `futuro.duke` aceitos |
| o cookie que não vence | sem o `Expires` e sem o `Max-Age` | `a_validade` e mais quatro | — | as fontes honestas: o cookie de 2023 vai |
| o salto pendente aplicado | o que passaria do teto, ou voltaria fora do envelope, segue pelo candidato | `alem_do_teto_fica_pendente` e mais seis | — | os pendentes: os −10 min aplicados sem ninguém confirmar |
| a confirmação de outra rodada | a rodada pedida não é comparada com a do pendente | — | `hora: a confirmacao nomeia a rodada` — a confirmação de A, com o pendente de B, não foi um conflito; `hora: confirmacao e rodada nova ao mesmo tempo` | os pendentes: a prova da outra rodada aplica o salto, em vez do `CONFLICT` |
| a contenção com o lógico parado | o NSF sem a suspensão | `com_o_logico_parado_a_contencao_por_taxa_fica_suspensa` | — | dois minutos adiantado: parado, o NSF pede o `net.block` da saída do operador |
| a revogação no meio da rodada | a decisão de `time.sync` não consulta a política de agora | — | `hora: revogacao e politica no meio da rodada` — revogado `time.sync`, a entrega passou pelo gate | a revogação: nenhuma recusa de hora do serviço, e a rodada segue |
| sem quórum | uma fonte basta | `uma_fonte_so_nao_move_nada` e mais cinco | — | o firewall: com duas barradas, o acordo de uma |
| a fonte divergente aceita | ela conta na cobertura, e não fica marcada | `a_divergente_fica_de_fora_e_marcada` e mais dois | — | a fonte divergente: acordo 3/3, sem marca |

### O que a validação do fechamento achou

A validação completa — aqui e no CI — achou cinco problemas fora do que o
fechamento mexia, e uma lacuna na própria bancada. Cada um foi reproduzido,
com a causa, o conserto, o caso que o fixa e a mutação reprovada. Dois deles
eram anteriores e conhecidos, com a proposta de conserto à espera: a CI
deste passo os reprovou, e o fechamento pede a CI verde.

- **O fio perdido no meio da conferência** (o kernel). No CI do ARM em
  release, a suíte perdeu o fio da bancada de hora no meio de `hora: cada
  resposta ruim e um veredito`, e toda rodada pela rede dali em diante
  fechou sem resposta de fonte nenhuma: treze casos. A conta do tempo põe
  o silêncio entre a resposta à primeira fonte e o pedido à terceira, na
  rodada da resposta repetida. A causa estava em `fios::bloquear_em` — ver
  "quem volta da cessão em `bloquear_em` volta rodando", acima: o fio que
  estacionava no primeiro núcleo e não saía dele conferia o futuro ainda
  marcado esperando; o `Dormir` pronto já tinha devolvido a vaga, e o
  quantum que vencia antes da volta a `Rodando`, com outro fio pronto no
  núcleo, o tirava dali esperando, sem waker. Dez execuções aqui não o
  reproduziram — seis filtradas, três inteiras e uma com estresse da
  bancada —; o caso `fios: a preempcao na conferencia nao perde o fio` abre
  a janela de propósito, e reprova o código de antes na primeira execução,
  no x86 e no ARM.
- **A incerteza que cai sem acordo** (a bancada). No CI do x86, o holdover
  falhou com `a incerteza diminuiu sem acordo`: a primeira rodada foi um
  acordo gradual, e com as fontes caladas a incerteza caiu 743 ms em 15 s,
  com o civil −753 ms. É o desenho: o que falta absorver do ajuste conta na
  incerteza (`hora::disciplina`) e sai dela à taxa do ajuste, 5%. A
  conferência, desde o T7.4, pedia mais que o desenho, e só passava quando
  a primeira rodada não deixava ajuste. `incerteza_sem_acordo` confere a
  propriedade do desenho — a incerteza só cai absorvendo um ajuste gradual,
  e nunca mais rápido que ele —, e um teste no hospedeiro a fixa, com os
  números do CI.
- **O descarte de um quadro só** (a suíte). Numa execução inteira do ARM em
  release, `firewall: descarta o quadro sem fluxo` contou dois descartes na
  injeção de um quadro. O retrato dos descartes de antes do caso mostrou de
  onde vem o outro: o fim de conexões que o kernel já tirou do conjunto — o
  RST do eco da bancada, o FIN e os dados atrasados do HTTP —, que o
  firewall descarta como sem fluxo, com razão; o caso de antes fecha duas
  conexões com o eco logo antes. O caso agora mede o descarte de um quadro
  só: nenhum descarte a mais é o datagrama entrando; mais de um é outro
  descarte na mesma volta da pilha, e a injeção se repete.
- **As sete regras de tempo, pelo nome** (a bancada). Das sete regras de
  tempo do NSF, a bancada conferia na imagem de produção duas pelo nome —
  a fonte divergente e o salto pendente — e o lógico parado pelo estado do
  `security.status`; as outras só se conferiam no hospedeiro, com
  registros iguais aos do kernel. Agora cada uma se confere no cenário que
  a dispara (ver "Onde se confere", acima), e a da assinatura num cenário
  novo, com a fonte forjada: o servidor assina a resposta com uma chave que
  a delegação não nomeia.
- **O RST que esperava o vizinho** (a pilha de rede). No CI do x86, em
  depuração, `firewall: descarta o quadro sem fluxo` não viu o firewall
  barrar o aviso da conexão que a regra derrubou: o contador não se mexeu.
  Já tinha acontecido uma vez, no ARM com virtio-gpu, e o gatilho de lá não
  se achou. Agora se achou: a captura do fio mostra que o emulador responde
  o ARP do `10.0.2.100` com um endereço Ethernet e manda os quadros IP de
  lá com outro, o do roteador. O `smoltcp` só renova a entrada de um
  vizinho com o tráfego que vem do mesmo endereço, e por isso ela vence
  sessenta segundos depois de cada ARP, com tráfego ou sem. Se vencia entre
  o SYN e a derrubada, o RST esperava um ARP, e a limpeza dos fechos tirava
  o socket — fechado — na mesma volta: o RST nunca saía. Nada vazava, mas o
  par de uma conexão derrubada não era avisado. O socket fechado com o RST
  por sair fica agora nos fechos até ele sair, ou dois segundos; o caso
  `firewall: o RST da derrubada espera o vizinho` esvazia a tabela de
  vizinhos antes de derrubar, e confere que o RST sai depois do ARP, barrado
  pela regra, e que o socket solta a vaga do dono com ele.
- **O `RESOURCE_LIMIT` dos fechos cruzados** (a pilha de rede). No CI do ARM
  em release, o programa `compressao` ouviu `RESOURCE_LIMIT` ao abrir uma
  conexão, sem conexão viva nenhuma. A causa foi medida no T7.3, nos casos
  dos cookies, e ficou como proposta: quando os dois FIN se cruzam, o
  emulador reconhece o nosso num segmento que repete o FIN dele com o número
  antigo; fora da janela, o `smoltcp` descarta o segmento inteiro, como a
  RFC 9293 manda, e o ACK com ele, e o nosso FIN só é reconhecido no
  reenvio, um segundo depois. No `CLOSING` daquele segundo, o fecho contava
  no teto do dono, e quatro fechos cruzados num segundo esgotavam as quatro
  vagas de um programa que abre uma conexão por pedido. O fecho agora
  termina também no `CLOSING`: o outro lado já fechou. O caso
  `rede: o fecho acaba quando o outro lado fechou` fixa a regra, estado a
  estado; o cruzamento em si depende do tempo da bancada, e não há caso que
  o provoque sempre.

| Problema | Mutação | Reprovada por |
|---|---|---|
| o fio perdido no meio da conferência | `bloquear_em` volta a rodar só na saída — o código de antes | `fios: a preempcao na conferencia nao perde o fio` — o fio preemptado não voltou, no x86 e no ARM |
| | `bloquear_em` sem volta nenhuma a rodar | `fios: quem volta do bloqueio volta rodando` e `fios: a preempcao na conferencia nao perde o fio`, no x86 e no ARM |
| a incerteza que cai sem acordo | a conferência estrita de antes | `sem_acordo_a_incerteza_so_cai_absorvendo_o_ajuste_gradual` |
| | a frouxa: qualquer queda passa | o mesmo |
| | sem o teto da taxa do ajuste | o mesmo |
| | o ajuste que não acaba de ser absorvido | o mesmo |
| o descarte de um quadro só | o datagrama UDP sem associação passa pelo firewall | `firewall: descarta o quadro sem fluxo` — o datagrama sem associação entrou |
| as sete regras de tempo, pelo nome | as cinco regras sem detecção — a assinatura, o salto, o salto além do envelope, a hora vencida e o lógico parado —, juntas | a bancada de tempo do x86, em release, cada cenário pela sua: a forjada sem `time-source-bad-signature`, a uma hora sem a observação `clock-jump`, os dez minutos sem `clock-jump-beyond-envelope`, a hora que vence sem `time-unauthenticated`, e o dia adiantado sem `logical-clock-stopped` |
| | o kernel aceita a resposta que a delegada não assinou | a bancada de tempo do x86: com a forjada aceita, o acordo é 3/3, e não 2/2; e `a_forjada_e_recusada_pela_assinatura_da_resposta`, no hospedeiro |
| o RST que esperava o vizinho | o socket fechado sai dos fechos na hora, com o RST por sair — o código de antes | `firewall: o RST da derrubada espera o vizinho` — o RST não saiu depois do ARP — e `rede: o fecho acaba quando o outro lado fechou`, no x86 |
| o `RESOURCE_LIMIT` dos fechos cruzados | o `CLOSING` não termina o fecho — o código de antes | `rede: o fecho acaba quando o outro lado fechou`, no x86 |

## O código de fora da imagem

O código da imagem roda porque é da imagem: veio com o kernel, com a
política e com as chaves, e quem tem a imagem tem tudo isso. O código que
chega depois — pela rede, gravado no armazém — não tem essa procedência:
qualquer um com `fs.write` no diretório o teria posto lá. A regra é uma
só, nas duas portas por onde código vira processo — o `user.run` e a
chamada `executar`:

- o código da **imagem** — os programas embutidos em `/bin`, os do disco
  em `/programas` — roda como sempre rodou;
- o código **gravado** em tempo de execução — o armazém — só roda com o
  **selo** de um **editor** do registro da imagem em que o **papel** de
  quem o lança confia.

A origem é a da montagem que a leitura percorreu, e não o caminho
escrito: `/armazem//compartilhado/./codigo/x` continua sendo o armazém.
E não há uma segunda política: a confiança num editor é uma linha da
mesma política, decidida no mesmo gate, com o mesmo papel; o selo é só a
prova de quem selou, como o aperto de mão é a prova de quem fala.

### O selo

O arranjo das assinaturas de módulo do Linux (`~Module signature
appended~`): o selo vai no fim do arquivo, depois do executável, sem tocar
nele — o ELF continua o mesmo, e o selo se separa dele pelo tamanho fixo e
pela marca no fim ([`sigilo::codigo`](sigilo/src/codigo.rs)).

```text
[ executável ][ assinatura Ed25519: 64 ][ chave pública do editor: 32 ][ "~Duke selo v1~\r\n": 16 ]
```

O editor assina o rótulo `Duke codigo: selo ed25519 v1` seguido do resumo
BLAKE2s-256 do executável — o mesmo resumo com que a auditoria nomeia o
programa: o que o editor assina é exatamente o que a auditoria cita. O
rótulo separa esta assinatura de qualquer outra feita com a mesma chave:
um selo não vale como assinatura de quórum, nem a assinatura crua do
resumo vale como selo. A conferência é a estrita (`verify_strict`), como a
do quórum: sem chave de ordem pequena e sem assinatura maleável, um selo
válido não tem uma segunda grafia que também valha.

Sem a marca no fim, o arquivo não tem selo: `CODE_UNSIGNED`. Com a marca,
ele **diz** que tem, e o resto tem de conferir — um selo cortado, uma
chave que não é ponto da curva, um byte do executável ou da assinatura
trocado depois: `CODE_TAMPERED`. O selo que confere, com uma chave fora do
registro ou com a de um editor em que o papel não confia:
`CODE_UNTRUSTED`.

O selo não diz **quando** o código foi selado, nem se é a versão mais
nova: prova **quem** selou **estes** bytes. O que o processo pode depois é
do papel e do manifesto, como para qualquer programa.

### Os editores e a confiança

O registro de editores mora na imagem, como o dos agentes:
`/etc/duke/editores`, uma linha por editor, `ed25519:<chave pública em
hex> <nome>`. A chave de ordem pequena é recusada na leitura — com ela,
nenhum selo conferiria, e o editor existiria só no nome. Em quem cada
papel confia é da política ([`politica::arquivo`](politica/src/arquivo.rs)):

```text
editores operador bancada
```

Sem repetição, em ordem; vazia é nenhum; num papel sem `process.run`, a
linha não diria nada, e é recusada. Muda pelo `policy.write`, com a prova
de um administrador, pela regra do teto: **tirar** um editor de um papel
é sempre possível — é a revogação da confiança —; **acrescentar**, só um
editor em que o próprio teto confia: ninguém concede a confiança que não
tem. A atribuição de um papel confere os editores como confere as
permissões, e o build da imagem confere que todo editor citado pela
política está no registro.

A política de desenvolvimento confia no editor `bancada` para o sistema, o
administrador e o operador, e dá ao operador e ao administrador
`process.run` em `/armazem/compartilhado/codigo`, onde o código instalado
mora. O registro da bancada tem um segundo editor, `outro`, em quem nenhum
papel confia; e a bancada tem uma terceira chave, `estranho`, que a imagem
não conhece. As privadas ficam em `target/chaves/`, como as dos agentes:
fora do repositório e fora da imagem.

### Onde se confere

[`usuario::codigo::obter`](kernel/src/usuario/codigo.rs) é o único lugar:
lê o arquivo **uma vez**, confere o selo sobre esses bytes e devolve esses
bytes — sem o selo — a quem vai carregar. Ninguém relê o arquivo entre a
conferência e a carga: quem trocasse o arquivo no armazém depois de
conferido trocaria um arquivo que ninguém mais lê. A ordem é a de quem
falha fechado:

1. o gate decide `process.run` sobre o caminho — no `user.run`, como
   qualquer comando; no `executar`, como `process.exec`, em nome do
   processo. Fora do alcance, o arquivo nem é lido;
2. `obter` lê, pela montagem, e confere a origem, o selo, o editor no
   registro e se o papel de **quem lança** — procurado agora — confia nele;
3. a recusa vai para a auditoria como a execução da decisão do gate —
   `DENY_POLICY`, o motivo e `; decisao N` —, e quem pediu ouve o porquê:
   o `user.run` responde `launched: false`, com o `code` e a explicação de
   razão `DENY_PROVENANCE`; o `executar` devolve `SEM_SELO` (−18),
   `SELO_NAO_CONFERE` (−19) ou `EDITOR_NAO_CONFIADO` (−20), e o processo
   segue inteiro — nada foi trocado;
4. o processo nasce com o editor no programa do fio, e a auditoria diz de
   onde ele veio — o nascimento, `processo <fio> lancado: codigo <resumo>
   de bancada`, e cada pedido dele, `(vindo <resumo> de bancada)`.

**A confiança é perguntada a cada pedido**, como o papel: cada pedido ao
registro, cada chamada de sistema que o gate decide e cada `fork` ou
lançamento feito por um processo de código selado perguntam de novo se o
papel ainda confia no editor. Tirada a confiança pela política, ou o
editor do registro, o pedido seguinte do processo que já está rodando é
`DENY_POLICY`, e ele não bifurca — o filho levaria o mesmo programa.

**O NSF vê o adulterado.** A regra `code-tampered` lê a mesma auditoria:
um selo que não confere é um código que mudou depois de selado, ou um selo
forjado, e basta uma vez. Mas quem pediu pode ser a vítima — o código veio
de uma fonte adulterada —, e a confiança da detecção é média; o NSF não
planeja contenção por ela: alerta, com o incidente, e a contenção fica com
quem tem a autoridade. O código sem selo e o editor em quem não se confia
são política, e não incidente.

O `xtask invariantes` confere o desenho: só `usuario/mod.rs` chama
`obter` e `programa::carregar`; nada mais em `usuario/` lê um executável
do VFS; só o carregador monta o programa de um fio; e o kernel não sela
nada — ele não tem chave de editor nenhuma.

### Da rede ao processo

O `xtask` compila o programa [`vindo`](programas/src/bin/vindo.rs) com os
outros, e **não** o põe na imagem: sela-o e publica cinco variantes no
servidor da bancada, `GET /codigo/<arquitetura>/<nome>`, claro e atrás do
TLS — selado pela `bancada`, sem selo, selado e com um byte trocado
depois, selado pela chave `estranho` e pelo editor `outro`. O
[`instalador`](programas/src/bin/instalador.rs) faz o caminho inteiro de
dentro de um processo, com a autoridade de quem o lançou: o nome
`bancada.duke` pelo DNS dele, a conexão decidida pelo gate, o TLS com a
âncora da imagem, o `GET`, e o corpo para o armazém pelo `fs.write`, no
anexo; depois bifurca, e o filho executa o arquivo gravado. Nada ali
decide nada: o selo é conferido pelo kernel na troca de imagem, e o
instalador só fica sabendo pelo erro.

```
instalador: baixou vindo: 26688 bytes
instalador: baixou vindo-sem-selo: 26576 bytes
instalador: baixou vindo-adulterado: 26688 bytes
instalador: baixou vindo-estranho: 26688 bytes
instalador: baixou vindo-outro: 26688 bytes
vindo: rodando, de fora da imagem
vindo: o gate deixou
instalador: rodou vindo: saiu 92
instalador: rodou vindo-sem-selo: saiu -18
instalador: rodou vindo-adulterado: saiu -19
instalador: rodou vindo-estranho: saiu -20
instalador: rodou vindo-outro: saiu -20
```

A suíte confere, além disso, a confiança tirada entre baixar e rodar, o
instalador isolado — que nem baixa nem bifurca —, a confiança tirada no
meio de um processo que já roda, e um fio que troca o arquivo entre o
selado e o adulterado enquanto outros o lançam: cada lançamento roda o
selado, ou é recusado. A fumaça grava as cinco variantes no armazém pelo
canal cifrado de um agente, pede `user.run` de cada uma e confere a
resposta e a auditoria.

### As medidas

A conferência — o resumo BLAKE2s do executável e uma verificação Ed25519,
sem a leitura do arquivo — é medida pelo kernel a cada vez
(`security.metrics`, em `code.verify_ns`), e a suíte escreve a média e a
maior a cada rodada, sobre o `ola` selado (20 KiB no x86, 22 KiB no ARM):

| | x86 | ARM |
|---|---|---|
| kernel de depuração | 3,5 a 8,3 ms (a maior, 26 ms) | 2,4 ms (a maior, 3,8 ms) |
| kernel de produção | 2,4 a 2,9 ms (a maior, 5,7 ms) | 1,5 a 1,8 ms (a maior, 4,7 ms) |

As faixas são de rodadas diferentes da mesma bancada — o emulador sem
aceleração, quatro núcleos —, e a máquina que o hospeda varia: a suíte
inteira do x86 em depuração levou de 24 a 30 minutos. Uma conferência
custa o que custam de três a oito decisões do gate na mesma rodada (2,4 ms
contra 0,68 ms no x86 em release; 1,5 ms contra 0,19 ms no ARM). Sem
emulador, na máquina que hospeda a bancada, só o resumo de 26 KiB leva
0,13 ms; a verificação Ed25519 é da mesma ordem.

Na fumaça — o kernel de produção, com o fio do NSF de verdade e o canal
cifrado de um agente —, a mesma medida, com a máquina ocupada, conta
também as vezes em que o fio que confere perde o núcleo: 7,7 a 7,8 ms em
média em depuração, 2,9 ms no ARM em release e 11 ms no x86 em release,
com a maior até 45 ms. O `user.run` inteiro, do lado do agente — o canal,
o gate, a auditoria, a leitura do armazém, a conferência e o nascimento —:

| `user.run` | x86 depuração | x86 release | ARM depuração | ARM release |
|---|---|---|---|---|
| o selado, que nasce | 129 ms | 56 ms | 164 ms | 25 ms |
| os quatro recusados | 378 a 421 ms | 84 a 139 ms | 389 a 505 ms | 19 a 28 ms |

Em depuração, a recusa custa mais que o lançamento: grava a execução da
decisão, monta a explicação e escreve o aviso no log, e o processo que
nasce só carrega depois da resposta.

No caso do instalador, cada download de 26 KiB — o DNS, a conexão, o
aperto TLS, o `GET` e a gravação no armazém pelo gate — leva de 0,9 a
1,1 s em depuração e de 0,5 a 0,6 s em release, nas duas arquiteturas; a
execução num filho — `bifurcar`, `executar` com a leitura e a
conferência, e a espera —, de 230 a 900 ms em depuração e de 60 a 220 ms
em release, recusada ou não. O código da imagem não paga a conferência: a
suíte confere que o `user.run` do `ola` da imagem não passa por ela.

### O que o exercício encontrou

- **O lançamento respondia antes de ler.** O `user.run` criava o fio e
  respondia `launched: true`; o fio lia o arquivo depois de nascer — e,
  para um caminho que não existia, morria sozinho, longe de quem pediu.
  Com o selo, a conferência teria de acontecer ali, num fio que já
  nasceu, sem resposta a quem pediu e com o arquivo lido depois da
  decisão. Agora `user.run` lê e confere antes de o fio nascer, responde a
  recusa a quem pediu, e entrega ao fio os bytes conferidos — e o caminho
  que não existe deixou de ser "lançado".
- **Lançar passou a esperar a leitura.** Com a leitura antes de o fio
  nascer, quem lança espera o arquivo ser lido e conferido, e um laço de
  lançamentos ficou em fila. Dois casos da suíte dependiam do lançamento
  que respondia antes de ler, e a suíte inteira os pegou — os casos
  `codigo:`, sozinhos, não: o do `ceder` lançava oito cópias em fila, e
  cada uma saía antes de a seguinte nascer, sem ninguém a quem dar a vez
  (16 trocas, e não milhares) — agora as lança de oito fios ao mesmo
  tempo, como antes os fios liam cada um o seu arquivo —; e o da
  revogação no meio do pedido HTTP revogava a chave 30 ms depois de pedir
  a página lenta — na máquina mais lenta, a recusa caía no envio, e não
  na leitura que o caso confere; agora espera a leitura ser decidida.
- **O `executar` não alcançava o armazém.** O nome que ele aceita tinha
  32 bytes, o bastante para `/bin/<nome>` e `/programas/<arquitetura>/<nome>`;
  `/armazem/compartilhado/codigo/vindo` tem 35, e o processo não
  conseguia executar o que ele mesmo tinha gravado. O teto agora é o de um
  caminho de `abrir`.
- **O filho levaria a confiança que o pai perdeu.** A contenção já
  impedia o processo isolado de bifurcar; a confiança no editor, não: o
  processo de código selado cujo editor saiu da confiança seria recusado
  em cada pedido, mas ainda bifurcaria e lançaria. Agora `fork` e o
  lançamento perguntam também.
- **A corrida não pega a releitura.** O caso que troca o arquivo entre o
  selado e o adulterado enquanto outros o lançam confere que cada
  processo carregou o que foi conferido. A primeira versão lançava o
  `ola`, que não faz pedido nenhum ao gate — e é o pedido que diz, na
  auditoria, o resumo do que foi carregado —; passou a lançar o
  `ponteiros`, que abre um arquivo. Mesmo assim, a mutação que relê o
  arquivo depois de conferir passou pelo caso: a releitura só carrega o
  adulterado se uma gravação inteira couber entre as duas leituras —
  alguns milissegundos —, e a leitura que pega uma gravação no meio é
  recusada (`o arquivo mudou depois de aberto`), oito de doze lançamentos
  naquela rodada. O caso continua valendo para o que ele confere; a regra
  "lê uma vez" virou uma conferência do `xtask invariantes`, que reprova
  a releitura sempre.
- **O instalador dependia do caso de antes.** O `fs.mkdir` cria um nível
  só, e o instalador criava só `/armazem/compartilhado/codigo`: o
  diretório de cima existia porque o primeiro caso da série o tinha
  criado. Rodado sozinho — numa mutação —, o caso do instalador falhava no
  download, antes de chegar ao que a mutação mexia. Agora o instalador e
  a fumaça criam os dois níveis.

- **A vaga do zumbi era livre.** No ARM em release, na CI, o caso da
  corrida lançou doze `ponteiros` — que bifurca e colhe — ao mesmo tempo,
  e um deles ouviu que não tinha filho nenhum (`a espera legitima deu
  Err(-11)`). A conta das vagas do escalonador tratava a de qualquer fio
  terminado como livre, e a do zumbi também — o filho que terminou e que
  o pai, vivo, ainda vai colher. O coletor já o respeitava; a criação de
  um fio, não: o fio que nascesse entre a saída do filho e a pergunta do
  pai ficava com a vaga, e o código de saída ia embora com ela. Um defeito
  de antes desta fase, que só a concorrência dela mostrou. A conta agora
  pula o zumbi, e o caso `fios: o zumbi guarda a vaga ate a colheita` o
  torna determinístico: o programa `colhedor` bifurca e só colhe quando a
  suíte manda, e no meio a suíte enche a tabela de fios.
- **O instalador passava da taxa.** No kernel de produção, os cinco
  downloads seguidos — umas vinte decisões do gate por arquivo — passam
  da taxa de todo dia do operador, e o quinto ouve `RATE_LIMIT`, como
  deve. No de depuração, mais lento, a taxa não chegava a ser alcançada.
  Os casos que usam o instalador sobem a taxa do operador, como o caso das
  medidas do HTTP já fazia. (Com o plano de dados, os downloads gastam a
  ficha só no controle — 43 decisões nos cinco arquivos, contra 72 de
  dados —, e os casos voltaram à taxa de todo dia: ver
  [O plano de dados](#o-plano-de-dados).)
- **O sono acordado por NMI.** Na CI, na suíte com a virtio-gpu, o caso
  `arch: dormir parado acorda com as interrupcoes mascaradas` reprovou
  logo depois do caso novo do zumbi: o coletor devolvia as pilhas dos
  fios que aquele caso criou, cada página com um aviso de descarte aos
  outros núcleos — uma NMI —, e o sono do caso acordava com uma delas
  antes de qualquer interrupção comum. A NMI não passa por `irq::total`, e
  o caso lia essa volta como "não dormiu". Com a suíte filtrada aos dois
  casos, na mesma máquina, reprovou cinco vezes em seis. Agora as NMIs
  atendidas são contadas sob `modo-teste`; a volta que só uma NMI explica
  não decide, e o caso dorme de novo até uma interrupção comum; e uma
  segunda metade dorme com um fio de outro núcleo avisando sem parar, e
  exige ver a volta por NMI.
- **A parada parava quem a conduzia.** Com a suíte filtrada a esse caso,
  o caso final — o estouro de pilha de propósito — pendurou: o coletor
  devolvia a pilha do fio que avisava, e um aviso de descarte mandado
  antes da parada chegou depois dela ao núcleo que conduzia o fim. A NMI é
  a mesma para o descarte e para a parada; o núcleo a lia como parada e
  parava a si mesmo, no meio do relatório — o sistema morria calado. Um
  defeito do caminho de falha desde a fase 6, só do x86: no ARM a parada
  tem uma SGI só dela. Com o fio avisando até o caso final e uma sonda na
  serial, uma rodada em quatro pendurou, com a sonda mostrando a NMI
  parando quem conduzia; com a correção, seis em seis passaram, três delas
  com a NMI atrasada chegando e sendo ignorada. Quem conduz a parada
  agora não para por ela, e o caso final pede, depois de ligar a parada,
  a NMI atrasada — sem a correção, pendura sempre.

### O que fica de fora

- **A revogação de um selo, ou de uma versão.** Um selo antigo do mesmo
  editor continua conferindo: não há lista de selos revogados, nem
  versão, nem data. Tirar a confiança é por editor, inteiro. Impedir a
  volta a uma versão velha é da atualização com rollback, da fase 14.
- **O registro em tempo de execução.** Um editor novo é uma imagem nova.
  Registrar um editor por uma operação administrativa com prova, como o
  `agent.register`, é possível no mesmo desenho, e não foi pedido.
- **Uma cadeia de editores.** Uma chave por editor, sem certificado, sem
  autoridade que assine editores, sem prazo de validade; a troca da chave
  de um editor é trocar a linha do registro.
- **A confiança por programa ou por diretório.** O papel confia no editor
  para tudo o que ele selar; o que cada programa pode depois é do
  manifesto e do papel, como sempre.
- **A imagem conferida.** O código da imagem roda por ser da imagem; quem
  prova a imagem é a cadeia de boot confiável, o incremento seguinte desta
  fase.
- **Um programa maior que um anexo.** O instalador grava o corpo num
  `fs.write` só, com o anexo de até 60 KiB; o armazém aceita arquivos
  maiores, por partes, e o instalador não as usa.
- **O instalador que espera a taxa.** Ele não espera a janela da taxa
  quando ouve `RATE_LIMIT`: a recusa sobe como veio. Os bytes de um
  download não gastam a ficha — são o plano de dados —, mas cada arquivo
  ainda custa umas nove decisões de controle (a conexão, as sementes do
  TLS, o relógio, a gravação), e uma série longa o bastante, depressa o
  bastante, alcança a taxa do operador.
- **A conferência guardada.** Cada lançamento lê e confere de novo, sem
  cache: o custo, medido acima, é pequeno perto do resto do lançamento, e
  um cache teria de ser invalidado por toda troca do arquivo, do registro
  e da política.

### As mutações do código selado

Trinta e nove mutações contra o que a conferência promete — o selo, a
origem pela montagem, a confiança decidida pelo papel e a cada pedido, a
leitura única, a auditoria, a resposta e o NSF — e contra o que o
exercício achou fora dela — a vaga do zumbi, o sono acordado por NMI e a
parada que parava quem a conduzia —, cada uma contra o que deve
reprová-la: os casos `codigo:`, `fios:` e `arch:` da suíte de quatro
núcleos, no x86, os testes do hospedeiro e o `xtask invariantes`; cinco
delas também contra o outro lado. **Trinta e nove reprovadas** — uma só
depois da conferência que o exercício acrescentou, e uma, de ponta a
ponta, equivalente.

| Mutação | Reprovada por |
|---|---|
| a conferência não estrita: a chave de ordem pequena confere | `codigo::testes::chave_de_ordem_pequena` |
| a assinatura não conferida | sete testes do selo no hospedeiro; de ponta a ponta, a bancada recusa publicar — a variante adulterada conferia —; só no kernel, `codigo: so o da imagem roda sem selo` — o adulterado rodou |
| sem a marca, um selo estranho em vez de "sem selo" | `codigo::testes::sem_marca_no_fim_nao_ha_selo` |
| o selo carregado junto com o código | `codigo: o conferido e o que roda` — o pedido do processo citou outro resumo que o do nascimento |
| o rótulo fora da mensagem assinada | `codigo::testes::o_rotulo_separa` — a assinatura crua do resumo valeu como selo |
| o armazém montado como imagem | `codigo: so o da imagem roda sem selo` — o código gravado rodou sem conferência |
| a origem pelo caminho escrito, e não pela montagem | o mesmo caso — `/armazem//compartilhado/./codigo/...` rodou o código sem selo |
| a carga sem a confiança no editor | o mesmo caso — o editor fora do registro rodou |
| o pedido do processo sem a confiança | `codigo: a confianca e decidida a cada pedido` — tirada a confiança, o processo continuou pedindo |
| a chamada de sistema sem a confiança | o mesmo caso — o `abrir` passou sem a confiança |
| bifurcar e lançar sem a confiança | o mesmo caso — o código selado bifurcou sem a confiança |
| a política confia em qualquer editor | `arquivo::testes::os_editores_de_codigo`; de ponta a ponta, `codigo: so o da imagem roda sem selo` |
| o administrador concede a confiança que não tem | `arquivo::testes::a_confianca_muda_dentro_do_teto`; de ponta a ponta, `codigo: a confianca e decidida a cada pedido` |
| a chave fora do registro vale como a do primeiro editor | `codigo: so o da imagem roda sem selo` |
| a chave fraca aceita no registro de editores | `registro::testes::editor_ida_e_volta_e_recusas` |
| a confiança num papel que não roda nada | `arquivo::testes::os_editores_de_codigo` |
| a atribuição de papel sem o teto dos editores | `arquivo::testes::a_confianca_muda_dentro_do_teto` |
| a carga relê o arquivo depois de conferir | o `xtask invariantes` — a conferência lê o executável duas vezes. A suíte **não** a reprovou: ver o que o exercício encontrou |
| o `executar` relê o arquivo | o `xtask invariantes` — um executável lido por fora da conferência |
| o programa do fio montado fora do carregador | o `xtask invariantes` |
| o kernel sela código | o `xtask invariantes` |
| uma terceira porta lê e confere código | o `xtask invariantes` — `codigo::obter` fora do ponto de execução |
| uma terceira porta carrega código | o `xtask invariantes` — `programa::carregar` fora do ponto de execução |
| a recusa do `executar` sem auditoria | `codigo: o instalador pela rede` — a recusa não foi gravada |
| a recusa do `user.run` sem auditoria | `codigo: so o da imagem roda sem selo` |
| o nascimento sem o selo | o mesmo caso — o nascimento não diz quem selou, nem o resumo |
| o programa sem o editor na auditoria | `codigo: a confianca e decidida a cada pedido` |
| o `user.run` sem o código da recusa | `codigo: so o da imagem roda sem selo` |
| a explicação sem a razão de procedência | `explicacao::testes::a_taxonomia` |
| o erro do `executar` confunde o adulterado com o sem selo | `codigo: o instalador pela rede` — `-18`, e não `-19` |
| o nome do `executar` volta a 32 bytes | o mesmo caso — o processo não executou o que gravou |
| a vaga do zumbi volta a ser livre — o defeito que o exercício achou | `fios: o zumbi guarda a vaga ate a colheita` — um fio novo tomou a vaga do zumbi |
| a volta do sono por NMI decide, como antes | `arch: dormir parado acorda com as interrupcoes mascaradas`, na metade sob avisos de outro núcleo — "voltou sem nenhuma interrupcao ter sido atendida" |
| as NMIs atendidas sem conta | o mesmo caso — a volta por NMI ficou sem explicação |
| o sono mascarado vira giro — a mutação para a qual o caso existe | o mesmo caso, na primeira metade |
| quem conduz a parada para com a NMI atrasada | `pilha: estouro e detectado` — o caso final pendurou até o teto do `xtask` |
| o NSF não vê o código adulterado | `o_codigo_adulterado_alerta_e_nao_contem`; de ponta a ponta, `codigo: o instalador pela rede` |
| o NSF com confiança alta no código adulterado | `o_codigo_adulterado_alerta_e_nao_contem`, no hospedeiro. De ponta a ponta, **equivalente**: o NSF não planeja contenção para esta regra em confiança nenhuma — a contenção automática é só da saída depois de sondagem —, e nenhum pedido sai |
| o NSF lê o motivo sem tirar o processo do detalhe | `o_codigo_adulterado_alerta_e_nao_contem` |

Duas tiveram de ser escritas de novo. A "assinatura não conferida" caía
na bancada, e não no kernel: o `sigilo` é o mesmo dos dois lados, e o
`xtask` confere cada variante antes de publicá-la — a mutação que vale
tira a conferência só do alvo sem sistema operacional. E cinco mutações
do caso do instalador, rodadas sozinhas, falhavam no download, antes do
que elas mexiam: era o `fs.mkdir` de um nível só, que o caso de antes
escondia — corrigido, as cinco foram reprovadas pelo que mexiam.

## O Internet Computer

O Duke fala com o Internet Computer (IC) de dentro de um programa: a
consulta anônima (*query*) a um canister — o ICP-1 —, e a chamada de
atualização (*update*), do anônimo ou assinada pela chave de uma
identidade do Duke — o ICP-3, em [A chamada assinada](#a-chamada-assinada)
—, com a resposta **verificada** contra a raiz da rede antes de ser
entregue. O ICP-4a deu ao TLS do programa as cadeias das autoridades
públicas — a P-384 e o RSA, só na verificação —, que a rede principal usa.
O ICP-4b liga a rede principal, só para ler — em [A rede
principal](#a-rede-principal). O ICP-4c dá à consulta a chave do ICP-3 — em
[A consulta assinada](#a-consulta-assinada). O ICP-4d move valor com a
chave, na bancada — em [O valor na bancada](#o-valor-na-bancada). O desenho
inteiro, as tabelas e o que fica de fora estão em
[`docs/ICP.md`](docs/ICP.md).

Nada disso é do kernel. O IC é um protocolo de programa, como o TLS e o
HTTP: o kernel não sabe o que é um canister, um Principal, o Candid ou um
método, e a política não tem uma palavra do IC — o gateway da bancada é um
destino do alcance, como os outros. O gate decide o que
sempre decidiu — se esta identidade, por este processo, fala com este
destino, agora —, e o programa prova para si o que os nós responderam. O
`xtask invariantes` confere o primeiro lado: o kernel e a política não
dependem do pacote `web3` e não dizem `icp`, `canister`, `candid`,
`dfinity`, `web3` nem `pocketic` — nenhum comando, permissão, política,
auditoria ou exceção de rede do IC.

### O caminho de uma consulta

```
/dados/icp/redes ──► DNS ──► net.connect ──► TLS 1.3 ──► HTTP/1.1 ──► IC
   (fs.read)        (udp)    (o gate)       (âncoras)    (POST cbor)
```

As redes em que o programa confia vêm de `/dados/icp/redes`, pelo
`fs.read` — o endpoint e a **chave da raiz** de cada uma: a chave nunca se
aprende da rede, e um endpoint que mente não troca a raiz. A conexão é a
de [`programas::http`](programas/src/http.rs): o nome pelo DNS do
programa, o destino pelo gate, o TLS com as âncoras da imagem. Por ela, dois
`POST application/cbor` — o `read_state`, que traz o certificado da
sub-rede do canister, e a `query` —, e cada `net.send` e cada `net.recv`
decididos de novo: a revogação, a contenção e o firewall valem no meio de
uma consulta.

A verificação é do processo, no pacote [`web3`](web3/src/icp.rs), `no_std`
como o `tls` e o `http`, e nada é entregue antes dela:

- o certificado: a delegação da raiz, de um nível só — uma aninhada é
  recusada —, a assinatura BLS de cada nível, o canister nas faixas da
  sub-rede e o tempo do certificado a no máximo cinco minutos da hora de
  quem confere. O BLS12-381 é o da DFINITY, `ic-verify-bls-signature`,
  reutilizado direto: `no_std`, conferido nos dois alvos dos programas;
- a resposta: a assinatura Ed25519 (ZIP215) de um nó **da sub-rede do
  certificado** sobre a resposta **deste pedido** — o nonce do
  `random.read` entra no id do pedido, e o id no que o nó assina;
- o Candid da resposta, com tetos: o truncado, o que sobra e o que não é
  Candid são recusados.

A hora de conferir é a dos consumidores ([Os consumidores da
hora](#os-consumidores-da-hora)): o civil quando autenticado, o lógico
quando não. As outras bibliotecas oficiais — `ic-transport-types`,
`ic-certification`, `ic-certificate-verification`, `ic_principal`,
`candid`, `ic-ed25519` — são **oráculos** dos testes do hospedeiro: cada
peça do `web3` é conferida contra a oficial, e nenhuma vai para um
programa. O `ic-agent` foi lido e não portado: traria o `tokio`, o
`reqwest`, sockets e DNS próprios e um repositório de raízes paralelo —
tudo o que o caminho do Duke já é, pelo gate.

### O que se prova não autoriza nada

| | prova | não é |
|---|---|---|
| o TLS | que o endpoint tem o nome pedido | a resposta do IC, nem autorização |
| a verificação do IC | que os nós da sub-rede do canister responderam isto a este pedido | `ALLOW` do Duke |
| o gate | que esta identidade pode falar com este destino, agora | nada sobre o canister |

Um Principal do IC nunca é identidade do Duke — a consulta é anônima, e
quem pede ao gate é o processo, com a autoridade de quem o lançou. Um
certificado, do TLS ou do IC, nunca é autorização, e uma verificação nunca
concede permissão: a suíte confere com a política que tira o gateway do
alcance — `DENY_RESOURCE`, nada enviado — e com a que tira
`audit.declare` do papel — a consulta verifica do mesmo jeito, e a
declaração é recusada.

### A declaração

O programa deixa o desfecho de cada consulta na auditoria pelo
`audit.declare` — *A declaração*, em [A política](#a-política) —,
genérico: uma **alegação** de quem pediu, ao lado dos fatos que
só o kernel sabe. O registro de uma consulta da fumaça:

```text
recurso  icp.query pi33i-pt777-77776-aaaaa-cai/ola verified
detalhe  pelo processo 41 (verificado 3f2a…): conexao 7 tcp:10.0.2.100:4943; decisao 1234
```

No recurso, o que o programa disse; no detalhe, o processo, o programa, a
conexão e o **destino real** dela pela tabela da pilha — ou `sem conexao`
— e a decisão do gate, que é a da permissão `audit.declare` do papel, sem
recurso. Nenhuma decisão lê a declaração: nem o gate, nem o firewall, nem
as cotas, nem a contenção. Ela gasta a taxa de quem lançou o programa, e
é recusada a um processo contido e a uma sessão que acabou. O desfecho é
uma palavra — `verified`, `verified_reject`, `unverified_<etapa>`,
`failed_<etapa>` —, e o NSF observa os `unverified*` com confiança baixa,
sem incidente, sem contenção e sem regra no firewall
([`docs/SEGURANCA.md`](docs/SEGURANCA.md)).

### A bancada

`cargo xtask test`, `cargo xtask fumaca` e, no ARM, `cargo xtask
iniciador` — que roda a suíte inteira pela UEFI — sobem a bancada do IC
([`xtask/src/icp.rs`](xtask/src/icp.rs)) antes da máquina:

- a **PocketIC 16.1.0**, o binário da release oficial da DFINITY, baixado
  uma vez e **conferido pelo SHA-256** antes de rodar, escutando só em
  `127.0.0.1`;
- a instância: a NNS e duas sub-redes de aplicação, e o canister da
  bancada na primeira — um módulo WebAssembly que o próprio script monta
  byte a byte ([`xtask/bancada/icp.py`](xtask/bancada/icp.py)), sem
  toolchain: `ola`, `eco`, `recusa` e três respostas de Candid fora da
  forma. A raiz, o canister e a sub-rede são os mesmos a cada instância
  desta versão, e a bancada confere os três: uma PocketIC que mudou é um
  erro da bancada, e não um caso falhando sem dizer por quê;
- o proxy, sem porta no hospedeiro: um `guestfwd` do emulador roda o
  script a cada conexão para `10.0.2.100:4943`, com o TLS 1.3 de
  `icp.duke` e `*.icp.duke`, e o nome que o cliente pede escolhe o que ele
  faz com a resposta — nada, segurar o `read_state` oito segundos, ou uma
  das nove mentiras: a raiz de outra rede, um bit da assinatura BLS, a
  resposta sem as assinaturas dos nós, o nó de fora da sub-rede, um bit da
  assinatura do nó, o nonce trocado no caminho, a delegação aninhada, o
  certificado da outra sub-rede e o certificado de quinze minutos atrás.

`/dados/icp/redes` tem catorze redes. Treze são da bancada — a honesta
pelo DNS, a lenta, as nove mentiras, a `direta`, honesta pelo endereço
fixo, e a `assincrona`, que responde a chamada com 202 —, todas para o
mesmo destino: o gate decide `tcp:10.0.2.100:4943`, e os nomes são do TLS
e do programa. A última é a `mainnet`, a rede principal, pelo DNS e com a
raiz dela, sem destino nenhum na política padrão.

### O que a suíte e a fumaça conferem

Na suíte (`icp:`), o programa [`icp`](programas/src/bin/icp.rs), lançado
por uma pessoa operadora e ditado por um canal de eventos, uma conexão
nova por consulta:

- **a consulta verificada pelo gate** — o texto, o eco, a recusa assinada
  e o Candid fora da forma recusado na leitura; uma conexão decidida em
  nome da pessoa por consulta; cada passo declarado, com a âncora do
  kernel; os dois canisters que não são Principal — o texto fora da
  base32 e o da bancada com um caractere trocado, que só a soma recusa —
  não saem do processo, cada um com o seu motivo; e nada do IC em
  registro nenhum fora das alegações;
- **cada prova adulterada recusada** — as nove mentiras, cada uma com o
  motivo dela, e o NSF observando a alegação, sem incidente nem pedido;
- **a revogação, a contenção e o firewall no meio da consulta**, com o
  programa dormindo na resposta lenta: a política sem o gateway
  (`DENY_RESOURCE` na leitura acordada, o fecho recusado), a sessão que
  acaba (`DENY_NOT_AUTHENTICATED` na leitura **e** na declaração), a
  contenção (`DENY_CONTAINED`) e a regra do firewall (`FIREWALL_BLOCKED`,
  e a declaração ancorada no número cortado); e a recuperação, a decisão
  de agora;
- **o alcance e a permissão são do gate** — sem o gateway, nada sai; sem
  `audit.declare`, a consulta verifica e a declaração é recusada;
- **duas consultas ao mesmo tempo**, de duas pessoas, cada declaração na
  conexão do seu processo.

Na fumaça, com o kernel de produção e a política padrão, o agente do
papel `operador` lança o [`verificado`](programas/src/bin/verificado.rs):
o `ola` e o `eco` verificados pela rede `direta` — o endereço fixo, porque
a imagem de produção não tem o DNS da suíte —, a prova da `bls-invalida`
recusada e cinco consultas medidas. Do lado de fora, a fumaça lê a
auditoria desde antes do lançamento: as oito declarações, cada uma com a
âncora do kernel no gateway; as decisões do processo, todas deixadas e só
do que a consulta pede; nada do IC em registro nenhum fora delas; nenhuma
recusa por taxa e nenhum registro perdido.

### As medidas do IC

A fumaça mede cinco consultas `ola` seguidas na imagem de produção, cada
uma numa conexão nova, por parte: a conexão (o TCP e o aperto do TLS — o
endereço é fixo, sem DNS), os dois pedidos, e o resto, que é a
verificação, com a hora e o nonce pelo gate. A mediana, em ms, no
emulador sem aceleração, quatro núcleos:

| kernel de produção | x86 | ARM |
|---|---|---|
| depuração | conexão 120, pedidos 100, verificação 130 — **430** (340 a 610) | conexão 210, pedidos 100, verificação 110 — **380** (340 a 620) |
| release | conexão 90, pedidos 70, verificação 80 — **260** (220 a 440) | conexão 80, pedidos 70, verificação 90 — **230** (220 a 240) |

O programa é sempre o mesmo, compilado com otimização; o que muda entre
as linhas é o kernel — o gate, a pilha TCP e a auditoria de cada pedido.
Rodadas diferentes da mesma bancada variam: a mediana do x86 em depuração
deu 360, 420 e 430 ms em três fumaças.

No hospedeiro, nativo, a mesma leitura e verificação — o certificado com a
delegação (duas assinaturas BLS), duas assinaturas de nó e o Candid,
sobre as respostas gravadas de uma consulta ao IC de mentira — leva
**5,5 ms** de mediana (5,0 a 9,2 ms em 50;
`cargo test -p web3 --release -- --ignored --nocapture medida`). Os 80 a
130 ms da verificação no emulador são a emulação: o mesmo código, sem
tradução de instruções, é vinte vezes mais rápido.

Na suíte (o kernel de teste, o x86 em depuração), do pedido do
`read_state` à linha do desfecho — sem a conexão, com a declaração —, uma
consulta verificada leva de 660 a 810 ms (mediana 730); a prova recusada
no certificado, de 290 a 490 ms, porque a consulta nem sai.

### As mutações do IC

Uma de cada vez, sobre a árvore do ICP-1, com o que a pega: os testes do
hospedeiro (`cargo test -p web3`), quando a mutação é do `web3`, e a suíte
do x86 só com os casos `icp:`, sempre. As dezessete morrem nas duas — as
duas do Principal, só depois de a campanha achar o furo do passo da
suíte (abaixo):

| mutação | no hospedeiro | na suíte |
|---|---|---|
| a assinatura BLS do certificado não é conferida | `a_assinatura_errada_e_recusada` | a `bls-invalida` verificou |
| a delegação não é conferida contra a raiz do arquivo | `outra_raiz_e_recusada`, `os_modos_adversarios` | a `raiz-errada` verificou |
| a delegação aninhada é aceita | `a_delegacao_aninhada_e_recusada`, `os_modos_adversarios` | a `aninhada` verificou |
| as faixas da sub-rede delegada não são conferidas | `as_faixas_da_delegacao`, `a_delegacao_sem_faixas_ou_so_na_forma_antiga` | a `faixa-errada` caiu na conferência seguinte — os nós não são da sub-rede do certificado —, com o motivo errado |
| o certificado velho é aceito | `o_tempo`, `a_hora_errada_de_quem_verifica`, `os_modos_adversarios` | a `velho` verificou |
| a assinatura do nó não é conferida — o id do pedido não prende a resposta | `a_assinatura_presa_ao_pedido_e_a_resposta`, `o_reply_inteiro_entra_no_que_se_assina` e mais dois | a `assinatura-errada` verificou |
| o nó de fora da sub-rede é pulado, e não recusado | `a_assinatura_de_um_no_de_fora` | a `no-de-fora` verificou |
| a resposta sem assinatura é aceita | `sem_assinatura_ou_com_assinaturas_demais`, `os_modos_adversarios` | a `sem-assinatura` verificou |
| o Candid com bytes depois dos valores é aceito | `mensagens_simples`, `mensagens_geradas_e_estragadas_contra_o_oraculo` | o `candid_sobra` foi lido |
| o Candid sem a mágica é aceito | `mensagens_simples` | o `candid_magica` foi lido |
| o Candid truncado é lido até onde der | `valores_fora_da_forma`, `todo_prefixo_concorda_com_o_oraculo` e mais um | o `candid_truncado` entregou `ab` |
| o programa lê a falha do certificado como verificada | — | a `raiz-errada` foi declarada `verified` |
| o programa declara sem a âncora | — | seis casos: a declaração sem o destino que o kernel conhece |
| a contenção não alcança a declaração (kernel) | — | contido, o `icp` declarou |
| o programa não pede o nonce ao gate | — | um `random.read` a menos por consulta |
| o Principal com o CRC32 errado passa da soma | `o_texto_malformado` | o segundo recusado pela forma, e não pela soma |
| o Principal fora da soma e da forma é aceito | `o_crc_corrompido_e_recusado`, `o_texto_malformado` e mais um | o segundo aceito |

**O que a campanha achou.** O passo do Principal inválido da suíte usava um
texto fora da base32, recusado antes da soma e da forma canônica: as duas
últimas mutações passavam pela suíte, e só o hospedeiro as pegava. O
passo ganhou o canister da bancada com o vigésimo caractere trocado — um
bit dos bytes, e não do CRC nem da sobra da base32 —, que só a soma
recusa, e a suíte passou a conferir o motivo de cada recusa: sem a soma,
a forma canônica ainda recusa, mas com outro nome. E a mutação das faixas
mostrou a defesa em camadas, do jeito que se quer: sem a conferência das
faixas, o certificado da outra sub-rede passa, e a resposta cai na
seguinte — os nós que assinaram não são da sub-rede do certificado.

### A rede principal

O ICP-4b é a primeira leitura da rede principal do IC: o programa
[`livro`](programas/src/bin/livro.rs) pergunta `icrc1_symbol` ao
livro-razão do ICP (`ryjl3-tyaaa-aaaaa-aaaba-cai`, na sub-rede raiz) pelo
caminho de sempre — o DNS, o `net.connect` pelo gate, o TLS 1.3 pelas
âncoras públicas, o HTTP/1.1 —, verifica a resposta pela raiz da rede
principal e só então diz o símbolo. O kernel, a política, o gate e o
`key.sign` não mudaram:

- a imagem tem a linha `mainnet` em `/dados/icp/redes` — `icp-api.io` pelo
  DNS e a chave da raiz da rede principal, que nunca se aprende da rede — e
  as âncoras públicas em `/dados/tls/publicas.pem`, as raízes ISRG X1 e X2,
  conferidas pela impressão ao montar o disco;
- nenhum destino da rede principal na política padrão. Um destino é um
  IPv4 concreto, dado a um papel pelo `policy.write` com prova, e o DNS só
  resolve: um que mente leva, no máximo, a um `DENY_RESOURCE`, a um
  `TLS_UNTRUSTED` ou a uma prova recusada;
- na suíte, `icp: a rede principal: o dns nao abre nada` confere cada
  mentira do DNS; no hospedeiro, quatro respostas que a rede principal deu
  de verdade são conferidas pela raiz dela;
- `cargo xtask mainnet` é a fumaça real, à mão e fora da CI: o pré-voo do
  TLS contra o perfil do programa, os destinos pelo `policy.write`, a
  consulta, a auditoria e a revogação, e o relatório em `target/mainnet/`.
  O fluxo `rede-principal.yml` a roda num runner do GitHub quando alguém o
  pede.

O resto — a configuração, o DNS, os casos, a fumaça real, as medidas, as
mutações e o que fica de fora — está em [A rede
principal](docs/ICP.md#a-rede-principal-icp-4b).

### A chamada assinada

O ICP-3 dá a uma identidade do Duke — uma pessoa, um agente — uma chave
Ed25519 que o kernel guarda, e ao programa a chamada de atualização
assinada por ela, sem uma segunda autoridade em lugar nenhum:

```
pessoa / agente ─► identidade ─► sessão ─► processo ─► manifesto + papel ─► gate
  ─► chave:<nome> ─► reconfirmação ─► auditoria (e journal) ─► assinatura
  ─► programa icp ─► Principal do IC ─► chamada ─► certificado verificado
  ─► audit.declare ─► NSF
```

- **A chave é da identidade durável**, nunca da sessão, do processo ou da
  credencial; o nome `chave:<nome>` se resolve no espaço de quem pede, e
  não há parâmetro de dono. Pessoa e agente seguem o mesmo caminho. A
  privada não sai do kernel: nenhum comando a devolve nem a recebe, e ela
  não aparece em resposta, erro, auditoria ou log.
- **Cinco permissões genéricas**, no fim da tabela: `key.create`,
  `key.read`, `key.sign`, `key.destroy` e `key.revoke` — esta só em
  `admin.execute`, com prova: anula, e não dá o uso a ninguém. O sistema
  e a política de emergência não têm nenhuma.
- **Uma decisão por assinatura**, e no commit tudo de novo; o registro da
  assinatura vai para a auditoria e para o journal **antes** de ela sair.
  O kernel assina um resumo de 32 bytes num domínio do registro da imagem
  — só `ic-request` —, e não sabe o que ele resume.
- **O programa faz o resto**: a pública vira o Principal, o resumo é o id
  do pedido, a chamada vai por `/api/v4`, a pendente é acompanhada por
  `request_status`, cada leitura outro pedido, assinado de novo, e cada
  certificado é verificado pela mesma verificação do ICP-1. A declaração
  do desfecho vai ancorada na decisão da assinatura, e o NSF a lê como
  alegação.
- **A lápide é para sempre.** A destruição, a anulação e a revogação do
  dono gravam a lápide no journal; o nome não volta, nem para o dono
  registrado de novo, e uma fotografia velha do disco é recusada. A
  assinatura pedida com uma chave morta é recusada pelo kernel, e o NSF a
  observa (`dead-key-used`), sem agir.

Na fumaça, o operador cria a chave dele e o `verificado` chama o `quem`
assinado por ela — o canister responde o Principal da pública que o
`key.read` deu — e do anônimo; do lado de fora, cada assinatura cita a
decisão dela, gravada antes, e cada chamada assinada é declarada na
decisão da sua assinatura. A chamada `contar` inteira, assinada, leva de
430 a 700 ms de mediana no emulador — de 10 a 70 ms a mais que a do
anônimo —, e o `key.sign` sozinho, de 10 a 30 ms. As dezessete mutações
pedidas — do gate de `key.sign` ao certificado adulterado — morrem, e mais
duas: a reconfirmação sem a contenção e a compactação sem as lápides.

Ver [`docs/ICP.md`](docs/ICP.md), *A chamada assinada*, para o caminho
inteiro, os desfechos, os casos, as medidas, as mutações e o que ainda
não existe — delegações, custódia no TPM, compartilhamento, exportação e a
rede principal.

### A consulta assinada

O ICP-4c dá à consulta a chave do ICP-3: uma identidade do Duke consulta
um canister com a própria chave — a **consulta assinada** — e com a
resposta provada pelo consenso — a **consulta replicada**, o método de
consulta pelo caminho da chamada. O kernel, a política, o gate, o
`key.sign` e o TLS não mudaram, e nenhuma decisão de arquitetura é nova:

- **a consulta assinada** vai como a chamada vai: as faixas pelo anônimo,
  a consulta assinada pelo `key.sign` — uma decisão do gate, uma só —, e
  a resposta conferida como a do anônimo, pelas assinaturas dos nós sobre
  este pedido, que leva o remetente. A declaração é `icp.query`, ancorada
  na decisão da assinatura;
- **sem a chave, nada vai do anônimo no lugar**: a chave que não se lê
  para antes da conexão (`failed_key`), e a assinatura recusada para a
  consulta antes de ela sair (`failed_signature`);
- **a replicada** é a chamada do ICP-3 num método de consulta: certificada,
  e declarada como chamada, `icp.update`.

Na suíte, a consulta assinada e a replicada, do anônimo e assinadas, na
sub-rede de aplicação e na raiz; o mesmo Principal pela consulta, pela
replicada e pela chamada; sem `key.sign`; a prova adulterada em cada modo
da bancada; duas consultas assinadas ao mesmo tempo com a mesma chave; e
a chave anulada no meio. Ver [A consulta assinada e a
replicada](docs/ICP.md#a-consulta-assinada-e-a-replicada-icp-4c).

### O valor na bancada

O ICP-4d move valor no IC com a chave de uma identidade do Duke, na
bancada: o saldo, a transferência de ICP pelo ICRC-1 e ICP convertido em
cycles pelo CMC, cada resposta verificada antes de chegar ao programa. O
kernel, a política, o gate, o `key.sign`, o domínio e o TLS não mudaram, e
nenhuma decisão de arquitetura é nova:

- **o valor não é recurso do Duke**: o kernel não sabe o que assina, e a
  permissão `key.sign` sobre `chave:<nome>` já cobria qualquer pedido do
  IC. O controle é por separação — que chaves cada papel usa, que ações
  cada programa declara —, e não por um limite, que obrigaria o kernel a
  interpretar o IC;
- **a transferência é uma chamada do ICP-3**, e o saldo, uma consulta do
  ICP-1: o `web3` escreve agora o Candid composto, com o tipo dado, e lê o
  ICRC-1 e o CMC pelos nomes — o que não tem a forma deles não vira bloco
  nem saldo;
- **a repetição não executa duas vezes**: a `carteira` sempre põe o
  `created_at_time`, e repete com os mesmos argumentos, assinados de novo —
  o ledger responde `Duplicate` com o bloco da primeira. Uma prova
  adulterada não vira bloco: a repetição mostra o que houve.

Na suíte, o saldo e a transferência assinada entre duas chaves do Duke; a
repetição pela rede honesta e pela que responde 202; a prova adulterada em
cada lugar; sem `key.sign`, nada se transfere, nem do anônimo no lugar; as
recusas do ledger; ICP em cycles pelo CMC, e a notificação repetida; a
mesma transferência por dois processos, que executa uma vez; e a chave
anulada no meio. Ver [O valor na
bancada](docs/ICP.md#o-valor-na-bancada-o-icrc-1-e-o-cmc-icp-4d).

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
abre do lado dele, e o hospedeiro manda o nome dela. E pela rede, o canal
por TCP, as sessões 5 a 8 — ver [O canal do agente por
TCP](#o-canal-do-agente-por-tcp). `agent.session` diz a um agente qual é a
sessão dele; `agent.sessions` lista todas, com quem está conectado e o que
se perdeu.

**Uma coisa que a serial não dava: a conexão.** A serial não enxerga quando
um cliente conecta ou cai, e convive com isso por um teto de ociosidade e
uma linha vazia que o cliente manda ao chegar. A porta enxerga: o
dispositivo avisa cada abertura, e o quadro que estava pela metade fica com
quem saiu. Uma resposta para uma porta sem ninguém do outro lado é
descartada e contada, e uma que ninguém lê não cresce sem fim.

**O que é de uma conexão não sai na seguinte.** A resposta a um aperto de
mão e a recusa dele são de uma conexão, e a porta as manda com a geração em
que o aperto chegou: a conferência é na trava que enfileira os bytes, e o
que não confere não sai. O CI mostrou por quê: o cliente da porta 1 esperou
dois segundos pela resposta — o kernel estava ocupado com quatro apertos —,
desistiu e reconectou; o kernel terminou o aperto da conexão que já tinha
caído, a resposta não saiu, e a recusa por ela não ter saído foi para a
conexão nova, que ouviu "a resposta do aperto nao saiu" no lugar da dela. O
caso `agentes: o quadro de uma conexao nao sai na seguinte` põe a troca de
conexão no meio do aperto, por um gancho da suíte.

O que a conferência não alcança é um limite do transporte: o dispositivo
avisa cada abertura pela fila de controle e entrega os bytes pela fila da
porta, e o driver colhe as duas a cada tique, o controle primeiro. Se,
dentro de um mesmo tique, um cliente abre, manda o aperto e fecha, e outro
abre e manda o dele, os bytes dos dois chegam juntos depois dos avisos, e
nada no fluxo diz de quem é cada um — o `virtio-console` não marca a
fronteira entre conexões. O kernel responde ao primeiro aperto, e a resposta
vai para quem está conectado, o segundo, que não a abre (o Noise a amarra ao
aperto de quem a pediu); a sessão cai, e quem reconecta num tique seguinte
entra. Fechar isso é coisa do protocolo do canal — um início de aperto que
recomeça a porta, e uma recusa que diga a que aperto responde —, e não do
driver, que só poderia jogar fora os bytes de todo tique ambíguo, e com eles
o aperto de toda reconexão rápida. Medido com uma sonda que abandonava o
aperto e reconectava na hora: nas quatro rodadas, uma das duas primeiras
voltas (0 ou 10 ms entre o aperto e o fecho) caiu assim, e a rodada com o
driver instrumentado mostrou os dois apertos entregues juntos, na geração
do segundo. A bancada não reconecta na mesma porta em seguida, e espera o
aperto inteiro em vez de desistir dele: com dois segundos de paciência, o
kernel de depuração — centenas de milissegundos por aperto, as portas uma
de cada vez — fez o CI encadear reconexões até cair nesse limite.

**Acima do transporte.** O enquadramento, o JSON-RPC e os comandos não
sabem por onde os bytes vieram: perguntam ao canal da sessão. Foi assim que
o TCP entrou — mais um caso, sem mudar nada em cima —, e é assim que o
vsock, para as máquinas virtuais, entraria. São sete
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
administrador delega. E os dos serviços, pela linha `servico`: `seguranca`,
do tecido de segurança, e `tempo`, do serviço de hora — ver
[O tecido de segurança](#o-tecido-de-segurança) e [O tempo](#o-tempo). Um
papel pode incluir outro (`@observador`), mas as
permissões **sensíveis** — `fs.read`, `fs.raw_read`, `keyboard.read`,
`debug.trigger`, `terminal.attach`, `time.sync`, `audit.declare`, as
administrativas — não atravessam a inclusão: cada papel que as tem as escreve. Não há curinga: `*` é um erro de
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
registro: número, o tempo lógico em milissegundos (o relógio civil com o
piso do journal — ver [O tempo](#o-tempo) e [Persistência](#persistência)),
o tipo de titular (kernel, sistema, serial, agente, pessoa, administrador ou
ninguém ainda), sessão, sessão de pessoa, identificador, chave pública,
papel, método, recurso, código e um BLAKE2s dos parâmetros. O titular e
a sessão de pessoa entram no elo: um registro de pessoa não vira um de
agente trocando um texto. Os parâmetros não entram — podem trazer o que um
agente escreveu, ou uma prova administrativa. Cada registro carrega o elo
do anterior, e o seu é o BLAKE2s do anterior com a codificação dele; mudar,
tirar ou reordenar um registro muda todos os elos dali para a frente. Na
memória, a cadeia mora num anel de mil e vinte e quatro registros; o que
sai pela ponta deixa o elo como âncora. No disco, ela vai inteira para o
journal, e atravessa o boot com os mesmos números e elos. `audit.head` dá
a cabeça para ancorar fora da máquina, e a fumaça refaz a cauda no
hospedeiro com o mesmo pacote. Uma enxurrada recusada por taxa grava o
primeiro e soma os seguintes, para não empurrar para fora o que importa.

**A declaração.** Quem quer deixar um fato seu na auditoria — um programa,
um agente, uma pessoa — o declara com `audit.declare`: o evento
(`<espaço>.<nome>`, fora dos espaços dos comandos), o assunto e o desfecho,
cada um numa forma fechada que o registro do comando confere antes do gate
— fora dela, `INVALID_ARGUMENT`, e nada chega à decisão. O kernel grava a
declaração na mesma cadeia, como execução da decisão do gate: a alegação no
recurso, como veio, e no detalhe só o que ele sabe — o processo e o
programa, o número da decisão e, se a declaração se ancora numa conexão de
quem declara, o destino real dela, pela tabela da pilha. A conexão de outro
titular, a que não existe e a que já fechou respondem o mesmo
`INVALID_ARGUMENT`, sem dizer de quem é; o processo não ancora na conexão
de quem o lançou. É uma alegação, e não um fato do kernel: nenhuma decisão
a lê — nem o gate, nem o firewall, nem as cotas, nem a contenção —, e ela
não autoriza, não nega e não muda nada além do registro. A permissão é
sensível e sem alcance: o operador, o sistema e o administrador a têm; o
observador e o tecido de segurança, não. Gasta a ficha do papel de quem
pede — a do processo é a de quem o lançou —, e o manifesto de um programa
a declara como qualquer outra.

**Os códigos.** `ALLOW`, `DENY_NOT_AUTHENTICATED`, `DENY_ROLE`,
`DENY_PERMISSION`, `DENY_RESOURCE`, `DENY_POLICY`, `RATE_LIMIT`,
`INVALID_ARGUMENT` e `ERROR`. Uma recusa chega ao agente como o erro
JSON-RPC `-32010` (ou `-32011`, para a taxa), com o código no `data`.

**Taxa.** Cada papel tem um balde — pedidos por segundo e rajada —, por
sessão e por chave: reconectar não enche o balde. O balde é do exercício
de autoridade: o envio e a leitura pela conexão já aberta de quem pede, e
o fecho dela, continuam decididos e gravados, mas não gastam ficha — ver
[O plano de dados](#o-plano-de-dados). O aperto de mão tem o seu
limite por porta, contado antes de qualquer conta: cada aperto custa ao
Duke duas trocas Diffie-Hellman, e quem não tem chave registrada pode
pedi-los à vontade.

**Administrar: prova e papel, os dois.** As operações administrativas —
`agent.register`, `agent.revoke`, `policy.assign`, `policy.write`, as de
pessoas (ver adiante) e `time.confirm` — só
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
frames — o heap tem 8 MiB — e é zerada antes de voltar. A comparação é em
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
- **O tempo lógico não volta.** O relógio civil — o RTC até o primeiro
  acordo das fontes de hora —, com um piso que é o tempo do último registro
  gravado.
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
- **A reposição tem a ordem das gravações.** O boot reaplica o journal com
  a ordem na mão, e o coletor de vencimentos — um fio preemptivo, que
  vence as mensagens com a ordem — espera. A suíte repõe o journal muitas
  vezes, para conferir que ele diz o que a memória diz, e repunha sem a
  ordem: numa rodada, o coletor venceu no meio da reposição uma mensagem
  recém-reposta, a entrega seguinte dela no journal já não a achou
  (`transicao de mensagem que nao existe`), e cinco casos do armazém caíram
  em cascata. Agora a suíte volta à imagem e repõe numa seção só, com a
  ordem, e a reposição confere a ordem ao entrar: sem ela, a suíte para na
  primeira vez, e não numa rodada em muitas.
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
(`tpm_ek`). Os números do journal saem de uma leitura só, com a trava
tomada uma vez: lidos em pedaços, um registro só de auditoria que o coletor
gravasse entre dois deles entraria em `audit_records` e não em `records`,
e a diferença diria um registro de estado a menos do que o journal tem —
a bancada viu isso na CI.

A bancada `cargo xtask persistencia` sobe a mesma máquina várias
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

É o começo do que a fase 13 chama de auditoria: se um agente pode fazer tudo
que uma pessoa faz, o registro precisa dizer qual dos dois fez.

**O primeiro botão.** A barra superior tem o **Limpar**, que aceita `press` —
ver a seção da barra, abaixo. As janelas também aparecem na árvore, como
`window`, com os widgets delas: o servidor de janelas e o Terminal as
montam com o toolkit, e a descrição é gerada deles — ver o toolkit, em
Userspace.

**O que ainda não há.** Consentimento: um `set_value` do agente troca o que a pessoa
estava digitando, e nada pergunta a ela antes. A árvore mostra o que está
digitado, e o log registra quem agiu, mas pedir licença é trabalho da fase 13.

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

**Pelo fio**, para quem mede a rede: `DUKE_CAPTURA=<arquivo>` grava em
pcap cada quadro que passa pela placa virtio de cada máquina que o `xtask`
sobe — `<arquivo>.0`, `<arquivo>.1`, na ordem em que sobem —, pelo
`filter-dump` do emulador, sem nada no hóspede. Só os cabeçalhos, 128
bytes por quadro: o que se lê é o TCP — as janelas, os segmentos, as
pausas —, no `tcpdump` ou no Wireshark. Foi como a janela de um segmento
apareceu (ver [A janela do TCP](#a-janela-do-tcp)).

```bash
$ DUKE_CAPTURA=/tmp/fumaca.pcap cargo xtask fumaca --release
$ tcpdump -nr /tmp/fumaca.pcap.0 'tcp port 80'
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
- [x] **Fase 9 — Rede nativa.** IP, UDP, TCP, DHCP e TLS. Com `smoltcp` em
      vez de escrever a pilha: escrever TCP do zero é um a dois anos-pessoa
      e não diferencia o Duke em nada. O que diferencia é o lado de cima: um
      programa não abre um socket do Unix, pede uma conexão ao registro,
      com o destino como recurso da política, e cada conexão vai para a
      auditoria. O canal do agente por TCP vira mais um transporte de
      sessão. Feito: a pilha IP sobre a placa virtio, com o endereço pelo
      DHCP, e a conexão TCP de saída como capacidade do registro —
      `net.connect`, `net.send`, `net.recv`, `net.close` —, com o destino
      enumerado na política, decidida a cada uso, de quem a abriu e
      derrubada quando o dono acaba; e o programa `discador`, que conversa
      com o eco da bancada de dentro de um processo; e a leitura que
      espera o evento da pilha — `net.recv` com `wait` —, suspensa sem
      prender o executor e decidida de novo na entrega; e o UDP, a mesma
      capacidade com datagramas, numa associação que só conversa com o
      destino decidido; e o DNS, como programa sobre o UDP — um nome não é
      recurso da política; e o TLS 1.3, como programa sobre o TCP, com o
      envio que espera espaço na fila de saída e os bytes do gerador pelo
      gate — um certificado prova um nome ao programa e não autoriza nada;
      e o canal do agente por TCP, mais um transporte de sessão — o mesmo
      aperto, a mesma chave, o mesmo gate, a mesma auditoria: a conexão não
      traz autoridade, e a chave só vale confirmada. Ver [Rede
      nativa](#rede-nativa). **Fase 9 completa.**
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
- [x] **Fase 12 — Comunicação de alto nível.** DNS → TCP → TLS → aplicação
      sobre a pilha nativa da fase 9, começando pelo HTTP/1.1, sem uma
      segunda política: o protocolo é do programa, e o gate decide o
      destino. Feito: o pacote `http` — o cliente puro, a URL, o pedido, a
      resposta pela RFC 9112 sem ambiguidade de enquadramento, os limites,
      o *keep-alive* —, e a família de cada falha, sem decidir nada; o
      transporte dos programas separando a recusa do gate, o firewall, a
      conexão recusada, a derrubada e o prazo; o HTTP de um programa, do
      nome pelo DNS dele à conexão decidida pelo gate, com o TLS no meio; a
      bancada HTTP, clara e cifrada; e as correções que o exercício pediu —
      a conexão cortada pelo firewall responde com o código dele, o DNS não
      esconde mais a recusa do gate, e o NSF lê a captura do DNS até o
      fim. HTTP/2 e HTTP/3, mTLS, a gestão de certificados, o NTP e o SIMD
      ficam para depois. Ver [O HTTP de um programa](#o-http-de-um-programa).
      **Fase 12 completa.**
- [ ] **Fase 12 — os incrementos de infraestrutura.** Sobre o HTTP/1.1,
      cada um separado, na ordem das dependências entre eles: os buffers
      do TCP; as taxas dos papéis, medidas sobre eles; a compressão e os
      cookies, do programa; o HTTP/2, com o ALPN no TLS; o NTP, a gestão de
      certificados e o mTLS, nessa ordem; o *proxy*; o HTTP/3, que depende
      do QUIC e começa por uma avaliação; e as otimizações de cifra, por
      último, medidas. Feito: os buffers do TCP — a janela era de um
      segmento, e passou a ser o buffer de 16 KiB, e uma leitura leva
      vários segmentos numa decisão do gate (ver [A janela do
      TCP](#a-janela-do-tcp)); as taxas dos papéis — o envio e a leitura
      por uma conexão aberta continuam decisões do gate, e saem da taxa do
      papel para um orçamento, com a auditoria segurando quem vai depressa
      demais (ver [O plano de dados](#o-plano-de-dados)); e a compressão do
      HTTP — `gzip` e `deflate`, negociados e decodificados no programa, com
      o teto antes de descomprimir, sem que o gate saiba (ver [A compressão
      do HTTP](#a-compressão-do-http)); e os cookies — o pote do programa,
      com as regras da RFC 6265 e da 6265bis, na memória do processo, sem
      virar identidade nem autoridade de ninguém (ver [Os cookies do
      HTTP](#os-cookies-do-http)); e o HTTP/2 — o cliente da RFC 9113, com
      o HPACK, pelo ALPN no TLS ou no claro com conhecimento prévio: várias
      correntes numa conexão que o gate decidiu pelo destino, sem que ele
      saiba delas, e o erro de uma corrente separado do da conexão (ver [O
      HTTP/2](#o-http2)). E o tempo, no lugar do NTP — a hora autenticada
      pelo Roughtime, de várias fontes com quórum, pelo serviço de hora e
      pelo gate, e o TLS e os cookies dos programas validando por ela (ver
      [O tempo](#o-tempo)).
- [ ] **Fase 12 — Web3: o Internet Computer.** Um protocolo de programa,
      como o TLS e o HTTP, sem nada no kernel nem na política: o Duke
      consulta o IC de dentro de um processo, pela conexão que o gate
      decide, e confere a prova antes de entregar a resposta. Feito: o
      ICP-1 — a consulta anônima verificada ponta a ponta, o pacote `web3`
      conferido contra as bibliotecas oficiais da DFINITY, a declaração
      genérica `audit.declare`, que nenhuma decisão lê, o NSF lendo a
      declaração como alegação, e a bancada da PocketIC com o proxy que
      mente (ver [O Internet Computer](#o-internet-computer)); e o ICP-3 —
      as chaves de assinatura das identidades pelo gate, no journal com
      lápide, e a chamada de atualização assinada e verificada, do
      anônimo também (ver [A chamada assinada](#a-chamada-assinada)); e o
      ICP-4a — o TLS do programa confere as cadeias das autoridades
      públicas, P-384 e RSA, com a cadeia, o nome e a validade tão estritos
      quanto antes (ver [`docs/ICP.md`](docs/ICP.md)); e o ICP-4b — a rede
      principal, só para ler, com a fumaça real (ver [A rede
      principal](#a-rede-principal)); e o ICP-4c — a consulta assinada pela
      chave da identidade, e a replicada (ver [A consulta
      assinada](#a-consulta-assinada)); e o ICP-4d — o valor na bancada: o
      saldo, a transferência do ICRC-1 que a repetição não executa duas
      vezes, e ICP em cycles pelo CMC (ver [O valor na
      bancada](#o-valor-na-bancada)). A gestão de canister, as delegações, a
      custódia no TPM, a rede principal com chave e com valor e o resto
      ficam para os incrementos seguintes — os que pedem, cada um, uma
      decisão nova.
- [ ] **Fase 13 — Consentimento e auditoria.** Se um agente pode fazer tudo
      que uma pessoa faz, o modelo de permissão precisa ser **mais** forte que
      o de um desktop comum, e não mais fraco. Três coisas: quem pediu — a
      pessoa na frente da máquina ou o agente pelo canal —, o que foi feito, e
      um registro que a pessoa possa ler depois e desfazer. Junto com o resto
      do que um desktop precisa: assinatura de código e cadeia de boot
      confiável. O sandbox por aplicativo é o manifesto da fase 7.
      Começou pela assinatura de código, sobre a rede da fase 12: o código
      que chega pela rede e é gravado no armazém só roda com o selo de um
      editor do registro da imagem em que o papel de quem o lança confia —
      conferido uma vez, no ponto de execução, sobre os mesmos bytes que se
      carregam, e a confiança perguntada de novo a cada pedido do processo,
      na mesma política e no mesmo gate. Ver [O código de fora da
      imagem](#o-código-de-fora-da-imagem). A cadeia de boot confiável, o
      consentimento e o desfazer são os incrementos seguintes.
- [ ] **Fase 14 — Hardware real e distribuição.** Instalador, atualização A/B
      com rollback, imagens assinadas, ACPI de verdade, NVMe, placa de rede
      real, watchdog. É onde projetos assim costumam morrer, e é por isso que
      vem por último: até aqui o emulador é hardware suficiente.

## Licença

MIT OU Apache-2.0, a critério de quem usa.

Partes da pilha gráfica são porte de código do Redox OS, sob MIT, com o
aviso de copyright deles — ver [`THIRD_PARTY.md`](THIRD_PARTY.md).
