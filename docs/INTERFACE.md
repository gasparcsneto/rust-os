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

### A taxa é do principal

O balde deixa de ser da vaga de sessão e passa a ser de quem responde pelo
pedido: a chave do agente, a serial. Um agente e os processos que ele
lançou gastam do mesmo balde — lançar um processo não multiplica a taxa —,
e um processo de um agente que desconectou não esvazia nem enche o balde
de quem está agora naquela porta. Pessoas e o sistema continuam sem taxa,
como hoje.

### O contexto do comando é do fio

`EM_EXECUCAO` passa a ser uma entrada por fio, e o que os handlers
perguntavam ao canal — "que sessão é esta?" — eles passam a perguntar à
autoridade decidida: `autorizacao::sessao_do_comando()` e
`coordenacao::titular_da_autoridade(…)`. O número global
`sessao::ATUAL` deixa de existir.

### Identidade de programa e manifesto

Cada executável do Duke leva uma seção `.duke.manifesto`, gerada pelo
pacote `programas` a partir de uma declaração no próprio programa: o nome
dele e as permissões que pretende exercer. O kernel a lê no `executar`, e
guarda no processo o nome, o resumo BLAKE2s da imagem e o manifesto.

- Permissão efetiva de um processo = papel de quem o lançou ∩ manifesto.
- Um executável sem manifesto não tem permissão nenhuma: é recusado em
  tudo que exige uma. O padrão é o menor.
- `bifurcar` herda o manifesto; `executar` troca pelo da imagem nova — e a
  interseção com o papel de quem lançou continua valendo, então trocar de
  imagem nunca escala.
- A auditoria grava o programa no detalhe de cada decisão de processo.

### Erros

Os de mecanismo continuam números negativos pequenos
(`protocolo::usuario::erro`). Os de serviço vêm na resposta, com o nome
do código da política — a mesma tabela que o agente lê. `pedir` só
devolve erro de mecanismo quando o pedido nem chegou a ser pedido: ponteiro
inválido, pedido grande demais.

### Versão da interface

`system.info` passa a dizer a versão da interface nativa. As chamadas de
mecanismo só crescem; os comandos do registro se descrevem — um programa
que precisa de um comando novo pergunta a `agent.describe` se ele existe,
como um agente.

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
- **Fase 9 — Rede nativa.** IP, UDP, TCP, DHCP e TLS com `smoltcp`, como
  estava — mas um programa não abre um socket do Unix: pede uma conexão ao
  registro, com o destino como recurso da política (`net.connect` com
  alcance de host), e cada conexão vai para a auditoria. O canal do agente
  por TCP vira mais um transporte de sessão.

As fases 10 a 13 não mudam. A 12 perde o "sandbox por aplicativo", que o
manifesto da 7 já é.

## Incrementos e estado

| Incremento | O que entra | Estado |
|---|---|---|
| 7.1 | contexto do comando por fio; principal derivado da autoridade; fim da sessão global | em andamento |
| 7.2 | `pedir`/`resposta`, `Chamador::Processo`, taxa por principal, runtime e programa nativo | — |
| 7.3 | manifesto e identidade de programa; permissão efetiva por interseção | — |
| 7.4 | mutações, matriz, fumaça, documentação | — |
