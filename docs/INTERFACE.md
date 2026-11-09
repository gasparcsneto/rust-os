# Interface nativa — desenho da fase 7

> **Estado: em implementação.** A fase entra em incrementos — ver
> [Incrementos e estado](#incrementos-e-estado) no fim. Este texto foi
> escrito antes da primeira linha, a partir do que o kernel já é.

O Duke não vai falar a ABI do Linux. Os programas dele são do Duke: falam a
língua do sistema, e o sistema os trata como trata uma pessoa e um agente —
pelo mesmo gate, com a mesma política, na mesma auditoria. Não há uma
camada que imite outro sistema por baixo, nem um caminho de "programa
convidado" que passe ao lado do registro.

## O que já existe, e o que falta

### O que os programas já têm

Dezessete chamadas de sistema (`protocolo::usuario::numero`), todas de
**mecanismo**: memória (`mapear`), processo (`bifurcar`, `executar`,
`esperar`, `sair`), descritores (`abrir`, `ler`, `escrever`, `fechar`),
eventos (`escutar`), superfícies (`superficie`, `controlar`, `descrever`,
`valor`) e o pseudo-terminal. Três delas já passam pelo gate —
`abrir`, `executar` e `terminal` —, por `autorizacao::autorizar_processo`,
com a autoridade que o processo herdou de quem o lançou.

### O que só agentes e pessoas têm

Todo o resto do sistema: as mensagens, os arrendamentos, a auditoria, a
política, o registro de agentes e pessoas, a árvore semântica, o estado da
máquina. São os 54 comandos do registro (`agent::registry`), que um agente
pede pelo canal e uma pessoa pelo interpretador — cada um declarando a
permissão que exige, decidido por `autorizacao::autorizar`, gravado na
auditoria.

Um programa não alcança nada disso. Para ele, o Duke é um Unix pequeno:
arquivos, memória, processos e janelas. As abstrações que distinguem o
sistema — identidade, sessão, autoridade, política, versão, arrendamento,
mensagem, auditoria, persistência — existem só para quem está do lado de
fora da máquina.

### O que a análise encontrou no caminho

Antes de abrir o registro aos programas, uma leitura de como os comandos
sabem **quem** os pediu:

1. **A sessão do comando é uma variável global.** Os handlers de
   `ui.act`, `ui.claim`, `ui.release`, `agent.session`, `agent.sessions`,
   `admin.challenge` e `admin.execute` perguntam `agent::sessao::atual()`,
   um `AtomicU8` do sistema inteiro, posto pelo despachante do canal. O
   interpretador não o põe. Resultado, hoje: uma **pessoa** que pede
   `ui.claim` no interpretador arrenda o campo **como a serial**, e o
   `ui.act` dela chega aos programas como "agente 0". É confusão de
   principal — o handler deriva quem age de um número de canal, e não da
   autoridade que o gate decidiu.
2. **O contexto do comando é um lugar só.** `EM_EXECUCAO`, que diz com
   que autoridade o comando deste fio roda, é uma vaga global, trocada e
   reposta por `como_comando`. Funciona porque hoje **todo** comando roda
   no mesmo fio — o executor, no núcleo 0. Com programas pedindo
   comandos dos próprios fios, em qualquer núcleo, dois comandos
   simultâneos trocariam a vaga um do outro, e um deles perderia a
   autoridade no meio.
3. **A taxa é por vaga de sessão, e troca de dono.** O balde de cada
   sessão é reposto cheio quando outra chave aparece na mesma vaga. Um
   processo de um agente que já desconectou, pedindo pela vaga onde agora
   está outro agente, alternaria o dono a cada pedido — e cada troca
   enche o balde. A taxa tem de ser do principal, não da vaga.
4. **A prova administrativa é por sessão do canal.** `admin.challenge`
   guarda o desafio na sessão de quem pediu. Um processo — e uma pessoa
   no interpretador — não tem sessão de canal: hoje a pessoa guardaria o
   desafio na vaga da serial.

Os quatro são corrigidos na camada responsável, antes de qualquer
programa pedir um comando — ver o incremento 7.1.

## Princípios

1. **Um vocabulário, três falantes.** A API do sistema é o registro de
   comandos. A pessoa o fala pelo interpretador, o agente pelo canal, o
   programa por uma chamada de sistema. O mesmo comando, os mesmos
   parâmetros, a mesma validação, a mesma resposta, o mesmo código de
   recusa. `agent.describe` descreve a superfície para os três.
2. **Um gate.** O programa pede por `autorizacao::autorizar`, com um
   chamador próprio — `Chamador::Processo` —, e só a licença que ela
   devolve chama o handler. Não há tabela de permissões de processo à
   parte, nem decisão fora daquele arquivo.
3. **O programa age por alguém.** A autoridade de um processo é a de quem
   o lançou — o sistema, um agente pela chave, uma pessoa pela sessão —,
   procurada a cada decisão: uma revogação vale na hora, também para o
   processo já lançado. Nada disso muda.
4. **O programa nunca tem mais do que quem o lançou, e pode ter menos.**
   Cada programa declara, no próprio executável, o que pretende fazer —
   o manifesto. A permissão efetiva é a interseção do papel de quem lançou
   com o manifesto. Um programa não ganha nada por ser executado; perde o
   que não declarou. Ver o incremento 7.3.
5. **A auditoria diz qual programa.** Um pedido de processo grava a
   autoridade (quem respondia por ele) e o programa (o que pediu).
6. **Duas camadas, cada uma com o seu custo.**
   - **Mecanismo**: chamadas de sistema pequenas, binárias e estáveis,
     para o que é caminho quente ou é objeto do processo — memória,
     processo, descritores, eventos, superfícies. Ficam como estão.
   - **Serviço**: uma chamada, `pedir`, que leva um pedido do registro e
     traz a resposta. JSON, como no canal: o pedido é validado pelo mesmo
     `registry::validar`, a auditoria resume os mesmos bytes, e um agente
     que lê a auditoria vê o pedido do programa do mesmo jeito que o seu.
     O custo do texto é o de uma decisão auditada, que já domina o pedido.
7. **Nada de Linux por baixo.** Não há números de chamada do Linux, nem
   `errno`, nem `/proc`, nem um tradutor. Os descritores 0, 1 e 2 continuam
   o que são por convenção de leitura, não por compatibilidade.

## O desenho

### `pedir` e `resposta`

```text
pedir(pedido, tamanho, resposta, capacidade) -> tamanho da resposta, ou erro
resposta(destino, capacidade)                -> tamanho da resposta pendente
```

O pedido é o mesmo objeto JSON-RPC do canal — `{"jsonrpc":"2.0","id":…,
"method":…,"params":…}` —, e a resposta, o mesmo envelope, com `result` ou
`error`. O `error` traz o código da recusa (`DENY_PERMISSION`,
`DENY_RESOURCE`, `RATE_LIMIT`, …) no mesmo lugar em que o agente o recebe.

A resposta pode não caber no buffer do programa, e o handler já executou:
um `message.send` mandou, um `message.read` entregou. Descartar a resposta
seria perder o efeito de vista — o programa não saberia o id da mensagem
que mandou. Então ela fica **pendente** no kernel, uma por fio, e
`resposta` a entrega quando o programa tiver onde pô-la. A pendente vive
num `politica::sigiloso::Texto`, como a resposta do canal: pode levar o
corpo de uma mensagem, e é apagada ao sair. O pedido seguinte descarta a
que não foi buscada.

### O chamador `Processo`

`autorizar` ganha um terceiro chamador. Quem pede é o fio atual, e a
autoridade é a dele:

| Autoridade do processo | Quem a auditoria grava | Papel |
|---|---|---|
| `Sistema` (servidor de janelas, Terminal) | sistema | o da linha `local` |
| `Sessao` de um agente, pela chave | o agente | o do agente, agora |
| `Sessao` da serial | serial | o da serial |
| `Pessoa`, pela sessão do console | a pessoa | o dela, agora; sessão que acabou recusa |

A mesma conta de `autorizar_processo`, que já decide as chamadas de
mecanismo. A diferença é que agora ela decide o registro inteiro.

### O que um processo não pede

- **As operações por prova** (`admin.challenge`, `admin.execute`). A prova
  é um desafio da sessão do canal, assinado pela chave do administrador;
  um processo não tem sessão de canal. Recusadas no gate, gravadas.
- **O que é do próprio canal.** `agent.session` responde sobre a sessão
  do canal de quem pede; para um processo, não há.

Tudo o mais está disponível, sob a política: um programa de um agente com
`message.send` manda mensagem; um com `ui.read` lê a árvore; um do sistema
lê `system.info` — se o papel `sistema` tiver a permissão, como hoje.

### O que só um processo pede

- **Os endpoints da malha** (`fabric.offer`, `fabric.withdraw`,
  `fabric.recv`, `fabric.ack`). Um endpoint é de um processo — o programa
  que o kernel carregou oferece a intenção — e some com ele. Uma sessão — o
  canal de um agente, o console de uma pessoa — procura, manda, consulta e
  cancela (`fabric.discover`, `fabric.send`, `fabric.status`,
  `fabric.cancel`), mas não abre endpoint. Recusadas no gate, gravadas. Ver
  [`MALHA.md`](MALHA.md).

### A taxa é do principal

O balde deixa de ser da vaga de sessão e passa a ser de quem responde pelo
pedido: a chave do agente, a serial. Um agente e os processos que ele
lançou gastam do mesmo balde — lançar um processo não multiplica a taxa —,
e um processo de um agente que desconectou não esvazia nem enche o balde
de quem está agora naquela porta.

Uma pessoa e o sistema continuam sem taxa no que pedem **por si**: ninguém
digita na velocidade de uma máquina. Mas o programa de uma pessoa pede
nessa velocidade, e cada decisão vai para a auditoria e para o journal —
então os processos de uma pessoa gastam o balde da sessão dela, e os do
sistema, o do sistema, com a taxa do papel. Encontrado relendo a 7.2:
como estava, um programa lançado por uma pessoa enchia a auditoria sem
limite.

O pedido quebrado — JSON inválido, método desconhecido, parâmetro errado —
passa pela mesma taxa antes de ir para a auditoria: custa o mesmo trabalho
e o mesmo registro. Antes ele ia direto, e um programa mandando lixo na
velocidade de uma máquina enchia a auditoria e o journal sem passar por
balde nenhum. Vale também para o canal do agente, onde o mesmo buraco
existia, mais estreito.

O plano de dados, mais tarde, mudou o orçamento e não o caminho: o envio e
a leitura pela conexão já aberta do próprio principal, autorizados pelo
gate, não gastam o balde — o que os limita é a capacidade do recurso e a do
caminho da auditoria, com a contrapressão pela espera da 9.2. O pedido
quebrado, o recusado e o de quem está contido continuam gastando o balde.
Ver [O plano de dados](../README.md#o-plano-de-dados).

### O contexto do comando é do fio

`EM_EXECUCAO` passa a ser uma entrada por fio, e o que os handlers
perguntavam ao canal — "que sessão é esta?" — eles passam a perguntar à
autoridade decidida: `autorizacao::sessao_do_comando()` e
`coordenacao::titular_da_autoridade(…)`. O número global
`sessao::ATUAL` deixa de existir.

### Identidade de programa e manifesto

Cada executável do Duke leva uma nota ELF de dono `Duke` e tipo 1, num
segmento `PT_NOTE`, com o manifesto em texto:

```text
duke-manifesto 1
nome visualizador
permite fs.read system.read
```

O programa o declara com `programas::manifesto!("visualizador", "fs.read",
"system.read")`, que monta a nota em tempo de compilação; o script de
ligação a põe no segmento de notas. O envelope da nota está em
`protocolo::usuario::manifesto` (o mesmo para quem monta e quem acha), e o
texto em `politica::manifesto`, lido e testado no hospedeiro.

- O kernel acha a nota em `elf::validar` e lê o manifesto em
  `programa::carregar`, antes do ponto de não retorno: um manifesto que não
  se lê — cabeçalho de outra versão, permissão fora do vocabulário, dois
  manifestos, nota que passa do fim — recusa a imagem, e o processo que
  pediu o `executar` continua intacto. Um manifesto ilegível não é um
  manifesto vazio.
- O processo guarda o programa (`autorizacao::Programa`): o manifesto e o
  resumo BLAKE2s da imagem. Ele troca junto com o espaço de endereços
  (`fios::adotar_imagem`), na mesma seção crítica: a imagem nova nunca roda
  com o manifesto da anterior.
- Permissão efetiva de um processo = papel de quem o lançou ∩ manifesto,
  decidida no mesmo ponto: `autorizar` (para `pedir`) e
  `autorizar_processo` (para `abrir`, `executar`, `terminal`). A recusa
  pelo manifesto é `DENY_PERMISSION`, com "o manifesto nao declara X" no
  detalhe.
- Um executável sem manifesto não tem permissão nenhuma — nem lançado pelo
  sistema. O fio de um processo que ainda não carregou a imagem também não
  (`Programa::SemImagem`). Um fio do kernel não tem imagem a atenuar.
- As permissões administrativas e `debug.trigger` não se declaram: um
  processo nunca as exerce, e declará-las recusa o manifesto.
- `bifurcar` herda o programa; `executar` troca pelo da imagem nova — e a
  interseção com o papel de quem lançou continua valendo, então trocar de
  imagem nunca passa do papel. A resposta de um pedido que a imagem
  anterior não buscou sai na troca: era dela, com o manifesto dela.
  Encontrado relendo a 7.3 — como estava, a imagem nova a buscava.
- A auditoria grava o programa em cada decisão de processo: "pelo processo
  N (nome resumo): …", com os quatro primeiros bytes do resumo — o nome é o
  que o programa diz ser, o resumo é o que ele é.
- `cargo xtask elf` confere que todo programa do disco declara um
  manifesto, menos `anonimo`, que existe para provar o padrão.

### Erros

Os de mecanismo continuam números negativos pequenos
(`protocolo::usuario::erro`). Os de serviço vêm na resposta, com o nome
do código da política — a mesma tabela que o agente lê. `pedir` só
devolve erro de mecanismo quando o pedido nem chegou a ser pedido: ponteiro
inválido, pedido grande demais.

### A fila e a vez da tarefa `programas`

`pedir` deixa o pedido no fio e o id do fio numa fila; a tarefa
`programas` do executor a atende. O executor é cooperativo — a tarefa o
divide com o canal do agente, o enlace, o pulso, o console e a barra —, e
por isso ela atende em vezes: cada vez tira da fila no máximo o orçamento
da vez (`nativo::ORCAMENTO_DA_VEZ`: 16 pedidos ou 2 ms, o que acabar
antes, e nunca menos de um), executa de novo, fora do orçamento, os
suspensos cuja espera acabou, e cede.

- **A ordem**: a da chegada. O orçamento é conferido antes de tirar o
  próximo id, e o tempo é o da vez inteira, desde o primeiro: o que não
  coube fica na fila, no lugar, para a vez seguinte. Um pedido nunca é
  cortado no meio — o tempo corta a vez depois do pedido que passou dele.
- **Uma vez cada**: o pedido mora no fio, e só sai de "enfileirado" para
  "em curso" uma vez, sob a trava do escalonador; um id repetido na fila,
  ou o de um fio que morreu com o pedido nela, é largado sem chegar ao
  gate — e conta no orçamento, como o atendido e o recusado pela taxa,
  que custa quase o mesmo.
- **Os suspensos**: executados de novo em toda vez, com a fila cheia ou
  vazia, fora da conta e do tempo do orçamento — no máximo um por fio,
  cada um uma vez, sem suspender de novo. Com muitos prontos de uma vez,
  a vez passa do orçamento por eles.
- **O ceder**: sempre, depois de cada vez, e não só quando o orçamento
  acaba: a vez que esvaziou a fila emendaria noutra no pedido que
  chegasse logo depois. As tarefas acordadas durante a vez rodam antes da
  seguinte. Com a fila vazia, a tarefa estaciona até um pedido — ou o fim
  da espera de um suspenso — a acordar.
- **Quem atende**: só a tarefa, no executor — `nativo::servir()`, lançado
  uma vez pelo `main.rs` — e, na suíte, que não tem a tarefa, quem espera
  um processo (`atender_pendentes`, que só existe nela), uma vez do mesmo
  orçamento por volta. O `cargo xtask invariantes` confere que os nomes
  que atendem a fila não aparecem fora do `nativo.rs` e da suíte, que o
  `servir()` é o laço de `servir_com` com o orçamento de produção,
  lançado uma vez, e que o orçamento é finito.
- **O que o orçamento não reparte**: a fila é uma só, na ordem da
  chegada — um titular com mais processos pedindo tem mais lugares nela.
  O orçamento devolve o executor às outras tarefas — o canal do agente, o
  enlace, o pulso, o console e a barra —, e não aos pedidos de outro
  titular.
- **O que não muda**: o gate, a taxa, a autoridade, a auditoria. O
  orçamento escolhe quando um pedido é atendido, nunca o que ele decide.

**A escolha, pela medida** (9/11/2026). A bancada `cargo xtask
disponibilidade`, com a carga `0,g2,1,2,3,2:2,0` — sem carga, dois
processos só girando (o controle), um, dois e três processos de um titular
pedindo sem parar, e dois em cada um de dois titulares —, 3 vCPUs (um
núcleo do hospedeiro livre) e uma medida temporária, nunca commitada, da
vez da tarefa e da fila de prontas do executor. A varredura, no x86_64 em
`release`, contra o código de antes (`5b44552`), com dois processos
pedindo e com dois titulares — a linha de antes é uma segunda rodada
dele; a tabela de antes e depois, mais abaixo, usa a primeira. Com dois
titulares, a serial foi a um p99 de 501 ms numa e de 196 ms na outra, e
a vez, a 498 e a 197 ms: sem orçamento, a vez depende de como os pedidos
se emendam, e muda muito de uma rodada para outra.

| Orçamento | p99 da serial / do TCP (ms) | a vez, p99 (pedidos, no máximo) | pedidos/s |
|---|---|---|---|
| antes: a vez até esvaziar a fila | 112 / 118 · 501 / 502 | 98 ms (863) · 498 ms (2 679) | 4 821 · 4 853 |
| só ceder | 114 / 107 · 301 / 301 | 98 ms (914) · 524 ms (3 112) | 4 981 · 5 689 |
| 1 pedido | 24 / 22 · 34 / 34 | 0,8 ms (1) · 1,5 ms (1) | 4 977 · 4 795 |
| 4 pedidos | 42 / 23 · 51 / 60 | 3,1 ms (4) · 4,1 ms (4) | 4 890 · 4 856 |
| 16 pedidos | 30 / 28 · 22 / 24 | 8,2 ms (16) · 12,3 ms (16) | 5 198 · 5 798 |
| 64 pedidos | 47 / 40 · 54 / 52 | 24,6 ms (64) · 32,8 ms (64) | 5 047 · 5 167 |
| 0,5 ms | 17 / 23 · 27 / 40 | 2,0 ms (6) · 2,0 ms (6) | 4 891 · 5 216 |
| 2 ms | 26 / 22 · 32 / 32 | 4,1 ms (22) · 4,1 ms (26) | 5 184 · 5 232 |
| 8 ms | 58 / 60 · 26 / 29 | 12,3 ms (84) · 12,3 ms (91) | 4 962 · 5 266 |
| **16 pedidos ou 2 ms** | 34 / 32 · 31 / 30 | 4,1 ms (16) · 4,1 ms (16) | 5 124 · 5 298 |

O controle, só girando, ficou num p99 de 50–74 ms em todas as rodadas da
varredura. Só ceder não muda nada — as vezes ainda esvaziam a fila. Com o
orçamento — menos o de 8 ms —, o canal volta abaixo do controle, e a
vazão não cai. A conta sozinha deixa a vez crescer com o custo de cada
pedido (64 pedidos: a vez a 25–33 ms no p99), e o tempo sozinho deixa a
vez juntar pedidos baratos demais (8 ms: até 91 numa vez, e o canal no
dobro com dois processos). Dezesseis pedidos ou 2 ms: em `release`, a vez
em 4 ms no p99 nos dois cenários — com a conta sozinha, 8 e 12 ms —, e a
conta segura os baratos; em depuração, com o pedido de uns 2 ms, a vez
fica em 12–66 ms (abaixo).

O critério, fixado antes da varredura: com dois processos e com dois
titulares, o canal até 1,5 vez o do controle e o maior silêncio até o do
controle mais 50 ms; a maior vez abaixo de 10 ms em `release`; e a vazão
em ao menos 90% da de antes — e, entre as contas que cumprem, a maior
(menos vezes por segundo, e menos do custo de cada uma, abaixo), com o
tempo como rede para o pedido caro. A maior vez e o maior silêncio, na
medida, não dependem do orçamento — a maior vez ficou em 50–61 ms com
qualquer um, até com um pedido por vez (ver o fim desta seção) —, e a
escolha usou, no lugar deles, o p99 da vez e a espera da serial na fila
de prontas do executor. Cada variante rodou uma vez; a diferença de canal
entre as que cumprem — de 17 a 51 ms no p99 da serial — é menor que a de
duas rodadas do mesmo código de antes.

Os p99 da vez são o teto do balde da medida em que caíram — 4,1 ms é
entre 3,1 e 4,1 ms. A vez passa do tempo porque ele é conferido entre os
pedidos, e o pedido que o passa corre inteiro.

**Antes e depois**, o código de antes (`5b44552`, a mesma bancada) contra
o orçamento, nas duas arquiteturas, em `release` e em depuração — com
dois e três processos pedindo, e com dois titulares:

| | p99 da serial (ms) | a vez, p99 | pedidos/s, depois/antes | a maior espera da serial na fila de prontas (ms) |
|---|---|---|---|---|
| x86_64, `release` | 116 → 34 · 165 → 50 · 196 → 31 | 98–197 ms → 4,1 ms | 108% · 102% · 102% | 164 → 43 · 312 → 55 · 258 → 50 |
| aarch64, `release` | 102 → 8 · 166 → 7 · 170 → 8 | 98–197 ms → 4,1 ms | 102% · 104% · 102% | 180 → 9 · 193 → 5 · 320 → 27 |
| x86_64, depuração | 521 → 119 · 948 → 95 · 844 → 105 | 735–1 057 ms → 12–66 ms | 82% · 79% · 90% | 760 → 165 · 1 056 → 180 · 841 → 292 |
| aarch64, depuração | 261 → 103 · 293 → 73 · 417 → 86 | 195–531 ms → 12–33 ms | 88% · 88% · 81% | 281 → 116 · 529 → 127 · 537 → 254 |

O pulso — um por minuto, e por isso um só dentro da carga em cada rodada,
no cenário de três processos — saiu de 10 a 140 ms depois do minuto
(antes, de 70 a 580 ms); o relógio da barra, que a bancada lê em segundos
e só mostraria um atraso de dois ou mais, ficou no segundo, antes e
depois. Em todas as rodadas, nas quatro configurações, cada filho do
`incansavel` recebeu a resposta de cada pedido dele, e o kernel contou
exatamente esses e o relógio de cada pai — nenhum pedido perdido,
atendido duas vezes ou trocado.

Em depuração, a vazão sob carga caiu 10 a 21%. Um pedido custa ali uns
2 ms, e a vez de 2 ms leva de um a três. A vazão cai sobretudo porque a
tarefa devolve o executor: as outras tarefas — o canal do agente, o pulso
e a barra — foram de 15–19% dele a 20–26%, e a tarefa, de 76–83% a
70–73%, nas duas arquiteturas. Cada vez custa uns décimos de milissegundo a mais — o pedido um
pouco mais caro na vez curta, o laço do executor e a própria medida, que
conta cada avanço —, e a cessão quase nada: fora de `atender_com`, a
tarefa ficou abaixo de 1,1% do executor. Com 8 ms, a vazão na depuração do
x86_64 ficou em 84 a 95%, mas a vez foi a 66 ms no p99, com o canal
parecido: o orçamento é o de `release`, que é o de produção. E um pedido
caro não se corta: em depuração, a vez de um pedido só ficou em 6–12 ms
no p99.

O laço é `nativo::servir_com`, o mesmo na produção e em cinco dos casos
`orcamento:` da suíte, que o rodam num executor de teste. O maior
silêncio da serial — o maior intervalo sem resposta na bancada — ficou em
72–292 ms em `release`, e em 0,3–0,9 s em depuração (o do TCP, em
69–161 ms e 0,17–0,62 s). A espera da serial na fila de prontas é a parte
que a vez da tarefa causava, e o orçamento a tirou; o que sobra são
paradas do fio do executor, que o orçamento não controla — o núcleo dele
é dividido com os outros fios, os processos da carga inclusive, em quanta
de 50 ms (no x86_64 em `release`, a maior vez, mesmo de um pedido só, e a
maior espera da serial depois do orçamento ficaram perto disso) —, e o
hospedeiro, com os três núcleos do QEMU ocupados.

**As mutações** (9/11/2026), uma de cada vez, cada uma desfeita antes da
seguinte, contra o código do `d63823b`: 37 — 22 no `nativo.rs` e 2 no
`incansavel`, pela suíte filtrada aos casos `orcamento:` no x86_64 em
depuração; 8 na bancada e 2 nas constantes e no laço de produção do
`nativo.rs`, pelos testes do hospedeiro; e 3 no `main.rs` e nos fios, pelo
`cargo xtask invariantes`. Reprovaram 34: o orçamento ignorado; o id
tirado antes de conferir o orçamento, e perdido; dois ids por volta; a
ordem invertida; o tempo conferido antes do primeiro, ou nunca; o tempo
contado em ciclos, ou o de produção em microssegundos lidos como
nanossegundos; o tempo recontado a cada pedido; o zero que não vale um;
o ceder apagado, ou só com a fila ainda cheia; a tarefa que não
estaciona; os suspensos só com a fila vazia, largados com ela cheia, ou
um só por vez; o largado que não conta; a resposta entregue ao pedido de
antes; o id posto de volta na fila; o comando executado duas vezes; a
chamada da suíte e o laço de produção sem o orçamento; as constantes sem
limite; uma segunda tarefa que atende a fila, e a chamada da suíte posta
nos fios de produção; o filho do `incansavel` que não conta as respostas;
e as conferências da bancada, uma por uma. As três que passaram:

- **os suspensos antes da fila** (`retomar_suspensos()` chamado antes do
  laço da vez, e não depois): equivalente. As duas ordens executam os
  suspensos prontos em toda vez, com a fila cheia ou vazia, e nenhum
  requisito fixa qual vem primeiro; ficou a de hoje, a fila primeiro.
- **o filho do `incansavel` sem conferir o `id` ecoado**: sem um defeito
  no kernel, não há troca de respostas para a conferência ver. Duas
  mutações a mais a puseram à prova, pelo mesmo filtro: a troca pura de
  duas respostas da mesma vez — cada fio recebe a do outro, nenhuma se
  perde nem se repete, e as contas fecham — reprovou pela conferência (no
  caso dos dois titulares, "a resposta do pedido … veio com o id …"; no de
  um titular, cada vez atendeu um pedido só, e não houve o que trocar); e
  a mesma troca, com a conferência desligada, passou em todos os casos. Só
  o `id` vê uma troca: a conferência fica, e a mutação dela, sozinha,
  passa por construção.
- **a integridade da bancada sem as respostas contra os pedidos**: o
  teste do pedido sem resposta tirava a resposta e deixava as `ALLOW` e as
  recusas pela taxa como estavam; a soma das duas passava das respostas, e
  outra conferência o reprovava. O teste foi reforçado (`3e3a384`) — uma
  resposta e uma recusa pela taxa a menos, juntas —, e a mutação, rodada
  de novo contra ele, reprovou.

Na última rodada de cada uma, das 39 — as 37 e as duas da prova do `id` —,
36 reprovaram; passam a equivalente, e a conferência do `id` sozinha e a
troca sem ela, que juntas mostram que só a conferência vê a troca.

### Versão da interface

`system.info` passa a dizer a versão da interface nativa. As chamadas de
mecanismo só crescem; os comandos do registro se descrevem — um programa
que precisa de um comando novo pergunta a `agent.describe` se ele existe,
como um agente.

A versão 2 (`native_interface: 2`, DN-3) é a do **contrato público
explícito** (DS-2): a lista conferida das chamadas, dos erros, dos tipos de
evento — o aviso da malha (`MALHA`, 9) entre eles —, dos bits do aviso,
dos tetos, dos códigos de serviço e dos comandos da malha com os
parâmetros mora em [`sdk/contrato.txt`](../sdk/contrato.txt), e o `cargo
xtask invariantes` confere que o protocolo, o registro e a política dizem
o mesmo. O que o kernel não conhece é recusado — uma chamada, um
parâmetro, um `notify` que não é canal do processo —, nunca ignorado em
silêncio. O SDK — o laço, os fluxos, as mensagens sobre um fluxo, o
modelo de projeto, o selo e a instalação — está em [SDK.md](SDK.md).

## O roteiro, reorganizado

A fase 7 deixa de ser a ABI do Linux. O que vinha depois dela muda de
sentido junto: escrita em disco e rede deixam de ser "o que um programa de
Linux espera encontrar" e passam a ser capacidades nativas, sob o mesmo
gate.

- **Fase 7 — Interface nativa.** Este documento: o registro como API dos
  programas, o contexto do comando por fio, a taxa por principal, o
  manifesto e a identidade de programa, e o runtime tipado do pacote
  `programas`.
- **Fase 8 — Armazenamento nativo.** O sistema de arquivos gravável,
  log-estruturado, como já estava — mas exposto como capacidades do
  registro (`fs.write`, `fs.create`, …, sob `fs.write` e o alcance de
  caminho da política), com versão por objeto, arrendamento para quem edita
  e cada gravação confirmada só depois de persistida. O que o journal do
  ponto 7 fez pelo estado administrativo, o armazenamento faz pelos dados
  dos programas.
- **Fase 9 — Rede nativa.** IP, UDP, TCP e DHCP com `smoltcp`, como
  estava — mas um programa não abre um socket do Unix: pede uma conexão ao
  registro, com o destino como recurso da política (`net.connect` com o
  destino inteiro, enumerado), e cada conexão vai para a auditoria. O DNS
  e o TLS são programas sobre essas conexões, e não serviços do kernel: um
  nome não é recurso, e um certificado prova um nome ao programa sem
  autorizar nada no gate. O canal do agente por TCP é mais um transporte
  de sessão: o mesmo aperto, a mesma chave no registro, o mesmo gate — sem
  uma permissão, um comando ou uma decisão a mais.

As fases 10 a 13 não mudam. A 12 perde o "sandbox por aplicativo", que o
manifesto da 7 já é.

## Incrementos e estado

| Incremento | O que entra | Estado |
|---|---|---|
| 7.1 | contexto do comando por fio; principal derivado da autoridade; fim da sessão global | feito |
| 7.2 | `pedir`/`resposta`, `Chamador::Processo`, taxa por principal, runtime e programa nativo; o JSON em `protocolo::json`, um só para o kernel e os programas; o Terminal só confirma com o Enter da pessoa ou de um agente | feito |
| 7.3 | manifesto e identidade de programa (nota ELF, `programas::manifesto!`, `politica::manifesto`); permissão efetiva por interseção em `autorizar` e `autorizar_processo`; o programa na auditoria; `xtask elf` exige o manifesto | feito |
| 7.4 | o que a releitura achou (a resposta que passava pelo `executar`, a taxa do programa de uma pessoa, o pedido quebrado sem taxa, o fio acordado no meio de um pedido), mutações, fumaça pelo executor de verdade, documentação | feito |
