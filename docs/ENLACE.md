# O enlace entre dispositivos

Este documento descreve o **estágio 1 de B-E1/B-E2**, o que está
implementado e testado: **Duke A → enlace → Duke B**, a malha de uma
máquina levada à de outra, pelo mesmo gate, a mesma política e a mesma
auditoria de cada lado. É a segunda metade do primeiro marco da malha
([MALHA.md](MALHA.md)): a primeira é aplicação → malha → aplicação, numa
máquina só.

O caminho de um pedido, de ponta a ponta:

```
programa da pessoa em A → gate de A (fabric.send e fabric.remote)
  → serviço enlace de A → net.connect pelo gate de A → Noise IK (a chave do Duke de A)
  → registro de dispositivos de B → relação → pessoa de B
  → gate de B (papel da relação ∩ papel da pessoa ∩ teto `remoto`)
  → malha de B → endpoint de um programa da pessoa de B
```

Nada disso passa ao lado do gate, e nada viaja como autoridade: o que chega
a B é um pedido de outro dispositivo, decidido em B pelo que B registrou.

## As decisões

As dez decisões do estágio, aprovadas antes da implementação:

- **D1 — o dispositivo é um principal próprio** (modelo D₂). Não é agente,
  nem pessoa: é outro Duke, relacionado a uma pessoa desta máquina por uma
  **relação** que o administrador registra com prova (`device.register`) e
  revoga (`device.revoke`), pelo `admin.execute`, com journal e lápide.
- **D2 — a identidade do dispositivo é a chave X25519 do Duke dele** (a de
  B2), e é ela que inicia o Noise IK. Nenhuma chave nova, nenhuma PKI,
  nenhuma autoridade criptográfica nova, nada do TPM além do que B2 e
  ICP-5 já fazem.
- **D3 — um enlace próprio**: prólogo próprio (`Duke enlace entre
  dispositivos v1`), quadro de início próprio (tipo 5), registro próprio,
  vagas próprias e um conjunto fechado de mensagens. O canal do agente não
  abre um enlace, nem o contrário.
- **D4 — a autoridade efetiva** em B é a interseção do papel da pessoa
  local, do papel da relação e do teto `remoto` da política, procurados a
  cada decisão e reconfirmados no commit. O programa de origem é
  **atestado** — vai à auditoria — e não é critério.
- **D5 — a persistência**: a relação, o registro do dispositivo e a lápide
  vão ao journal; todo o resto (enlaces, pedidos a caminho, suspensões) é
  volátil. Não há armazenamento-e-envio.
- **D6 — a revogação** é local e permanente, com lápide na chave; a
  suspensão é contenção volátil. Nenhuma das duas se propaga a outro Duke.
- **D7 — o endereço é configuração**: o da relação, na origem. Não há
  descoberta.
- **D9 — o vocabulário**: `fabric.remote`, `device.register`,
  `device.revoke`, `device.suspend`; as linhas `remoto` e `servico enlace`
  da política.
- **D10 — a relação é (dispositivo, id, pessoa)**: um dispositivo pode ter
  relações com várias pessoas desta máquina, uma por pessoa.

**Uma divergência**, já combinada: o enlace escuta numa **porta TCP
própria, a 7071**, e não na 7070 do canal do agente com outras vagas. A
pilha (`smoltcp`) não escolhe o conjunto de vagas pela mensagem que ainda
vai chegar: numa porta só, um enlace podia ocupar a vaga de um agente, ou
o contrário. Com a porta própria, as quatro vagas do enlace (5 a 8) são só
dele, e o firewall só deixa um SYN entrar nela enquanto houver uma
relação.

## A identidade e o registro

O registro de dispositivos (`kernel/src/dispositivos.rs`, sobre a conta
pura de `politica::dispositivos`) guarda, por chave:

- o **nome** local, único (`par`), pelo qual a pessoa e os programas o
  pedem — `dispositivo:par`;
- as **relações**: o id (16 bytes, o mesmo nos dois Dukes), a pessoa desta
  máquina, o papel da relação e, na origem, o **endereço**
  (`tcp:<ipv4>:<porta>`).

Uma chave é **uma espécie de principal**: a deste Duke, a de um agente, a
de um administrador — de agora ou revogado — e a que tem lápide não entram
como dispositivo, e o registro de agentes recusa a chave de um
dispositivo. `device.register` exige que o papel da relação caiba no do
administrador que prova.

`device.registry` (pela serial, com `agent.read`) mostra os dispositivos,
as relações, as lápides (pela impressão), os enlaces de pé, os pedidos a
caminho e se a porta do enlace escuta.

No journal: `DISPOSITIVO_REGISTRADO` (42) e `DISPOSITIVO_REVOGADO` (43), na
fotografia, na diferença, na base da compactação e na reposição do boot.

## O enlace

- **Transporte**: TCP na 7071, as vagas 5 a 8 do canal (`rede::canal`), com
  a vida, os prazos e o fecho das do agente, e a contenção de apertos da
  política (`apertos 10 10000`), numa conta à parte por vaga.
- **Aperto**: Noise IK com o prólogo do enlace. O iniciador manda, cifrada
  na primeira mensagem, a **época** da origem (`{"epoch":"<16 hex>"}`); o
  respondedor confere a chave contra o registro de dispositivos e a
  contenção antes de responder. Autenticado não é relacionado: a chave que
  provou ser de quem diz ainda precisa estar no registro.
- **Confirmação**: o enlace só conta como de pé depois do primeiro quadro
  de dados que abre — é aí que a auditoria grava `link.open` com `ALLOW`.
  Um aperto que não chega a isso é gravado como recusado.
- **Mensagens**: uma por enlace, numa linha JSON cifrada —
  `{"relation":"<32 hex>","program":"<64 hex>","rpc":{…}}` —, e a resposta,
  o envelope JSON-RPC do gate de lá. Até 8 KiB. O conjunto é **fechado**:
  `fabric.send`, `fabric.discover`, `fabric.status` e `fabric.cancel`, sem
  `device` (um pedido de outro dispositivo não vai a um terceiro).

## A origem

`fabric.send`, `fabric.discover`, `fabric.status` e `fabric.cancel` com
`"device":"dispositivo:<nome>"`:

1. **O gate daqui decide duas vezes**, na mesma decisão: a permissão do
   passo sobre a intenção e `fabric.remote` sobre o dispositivo. Só quem
   age por uma **pessoa** fala com outro dispositivo — a pessoa no
   console, ou um processo dela —; um processo precisa do manifesto
   declarando `fabric.remote`. O nome se resolve **no espaço da pessoa**:
   o dispositivo de outra pessoa não existe para quem pede
   (`DENY_RESOURCE`). Suspenso, `DENY_CREDENTIAL`.
2. O pedido entra na **tabela da origem** (`politica::enlace`), na ordem
   das gravações e **reconfirmado** — a política que perdeu
   `fabric.remote`, o dispositivo revogado ou suspenso entre a decisão e o
   commit recusam aqui, e nada entra na fila; quem pede **suspende**. O nonce do
   processo é mapeado para o nonce do enlace daquela relação: o reenvio
   com o mesmo nonce é o mesmo pedido; um nonce velho é replay, recusado
   aqui sem gastar nonce do enlace.
3. O **serviço `enlace`** (`Servico::Enlace`, com o papel da linha
   `servico enlace`) toma o pedido, confere de novo que a relação está
   ativa e o dispositivo não está suspenso, conecta ao endereço da relação
   **pelo gate** (`net.connect`, `net.send`, `net.recv`, `net.close`, cada
   um decidido e gravado), faz o aperto com a chave do Duke e leva a linha.
   O que a revogação, a suspensão, o prazo ou o fim de quem pediu tirou do
   caminho não chega ao par — nem o aperto, se saiu antes dele, nem a
   linha, se saiu durante ele.
4. A resposta acorda quem esperava, e a reexecução a lê: `{"ok":…,
   "device":…,"remote":{…}}` — a resposta da malha de lá — ou a recusa,
   com o código de quem recusou.

O estado e o cancelamento de uma entrega mandada a outro dispositivo só
resolvem para o canal que a mandou.

## O destino

Cada pedido que chega por um enlace confirmado vai ao gate como
`Chamador::Remoto` — o dispositivo, a relação, a época da origem e o
programa atestado:

- **quem**: o titular `device`, o nome do dispositivo, a chave dele, o
  papel da relação; o detalhe da auditoria diz `pela relacao <8 hex>,
  atestado <8 hex>`;
- **a decisão**: o papel da relação, e então todos os três — relação,
  pessoa, `remoto` — pela mesma conta da política. O primeiro que não
  permite recusa, e a auditoria diz qual. Sem a linha `remoto`, nada
  remoto passa;
- **a reconfirmação**: a relação, a pessoa e os papéis são procurados de
  novo no commit — uma revogação no meio não escapa;
- **a taxa**: pela relação;
- **a malha**: o canal remoto (dispositivo, relação, época), com a pessoa
  da relação como titular — a entrega só chega aos programas dela.

## Suspensão e revogação

- `device.suspend` / `device.resume` (contenção, pelo gate e pela prova):
  o aperto do dispositivo é recusado, os pedidos dele também, nada daqui
  vai a ele, e os enlaces caem. Volátil.
- `device.revoke`: todas as relações saem, a chave ganha **lápide** — não
  volta, em registro nenhum —, os enlaces caem na hora, as entregas vivas
  do dispositivo são anuladas, e os pedidos daqui a ele falham, acordando
  quem esperava. Sem relação nenhuma, a porta do enlace deixa de escutar.

## Auditoria e proveniência

De cada lado, a auditoria única de sempre:

- na origem: a decisão do pedido (`intencao:… ; dispositivo:…`), a fila, o
  `net.*` do serviço, e o desfecho (`respondido pelo par`, ou a recusa);
- no destino: `link.open` (o aperto completo, com o nome e a chave; o
  recusado, com a chave alegada e o motivo), e cada pedido decidido pela
  relação, com o programa que a origem atesta. O motivo de cada recusa de
  lá cabe inteiro no teto do detalhe (96 bytes) depois da relação e do
  programa — um comando de fora do conjunto fechado é recusado por isso,
  antes de qualquer outra conferência.

## O que fica de fora

Pareamento, `device.pair`/`device.forget`, descoberta local, broadcast,
nuvem, conta central, propagação da revogação entre Dukes, armazenamento-
e-envio, handoff, recursos remotos, o programa de origem como critério,
criptografia ou autoridade nova, um segundo gate ou uma segunda
auditoria. O autosserviço da pessoa (D8) é do estágio 2.

## Testes

- **Hospedeiro**: `politica::dispositivos` (o registro, a lápide, a
  coerência), `politica::enlace` (o conjunto fechado, a tabela da origem,
  os nonces, as cotas, a anulação), `politica::malha` (o canal remoto),
  `sigilo` (o prólogo e o quadro do enlace, que não abrem no canal do
  agente).
- **Suíte** (x86 e ARM): os casos `dispositivos:` e `enlace:` — o registro
  com prova, as recusas, a revogação permanente, uma chave uma espécie, a
  suspensão; a entrega pelo enlace, o conjunto fechado, a autoridade
  composta, o aperto contra o registro, o replay e o reenvio, a revogação
  e a suspensão derrubando o enlace, a revogação no meio (na
  reconfirmação), a origem que decide e leva, as recusas da origem — cada
  uma da decisão, sem `ALLOW` nenhum —, a revogação com o pedido a caminho,
  a revogação no meio do aperto do serviço, a origem que reconfirma no
  commit (a política e a revogação entre a decisão e a fila), e mandar e
  revogar ao mesmo tempo.
- **Bancada de duas máquinas** (`cargo xtask enlace`): dois Dukes de pé ao
  mesmo tempo, cada um com o disco, o TPM e a chave dele, ligados só pela
  rede do emulador e pela ponte da bancada. O administrador registra a
  relação nos dois; a pessoa entra no Terminal das duas pelo teclado; o
  `carteiro` (um programa da pessoa em A) procura, manda, reenvia e
  pergunta o estado ao `correio` (um programa da pessoa em B); a auditoria
  dos dois lados é conferida. Depois: a suspensão em B e em A, o corte de
  energia de B (a relação volta do journal), a revogação em B (a lápide,
  também depois de outro corte; a porta fechada) e em A. Nos quatro pares:
  x86_64→aarch64, aarch64→x86_64, x86_64→x86_64 e aarch64→aarch64.
- **Mutações**: vinte e nove, uma de cada vez — seis nas contas puras e
  no `sigilo` (hospedeiro), vinte no kernel (os casos `enlace:` da suíte
  x86) e três que só a bancada mostra (a porta que escuta sem relação, a
  lápide e a relação que não voltam do journal). Todas reprovam. Na
  primeira rodada sete sobreviveram, porque os casos conferiam só o
  código, e outra camada devolvia o mesmo; os casos passaram a conferir o
  motivo inteiro de cada recusa, nenhuma decisão `ALLOW` onde a origem
  recusa, a política que deixa um comando de fora passar pela relação,
  pela pessoa e pelo teto, a revogação no meio do aperto e a reconfirmação
  da origem — e acharam dois motivos de recusa remota que passavam do teto
  do detalhe da auditoria. A tabela está no README.

## Medidas

Pela bancada, com cada pedido num enlace novo (a conexão pelo gate, o
aperto, o pedido, a decisão e a execução lá, a resposta), kernels de
debug e as duas máquinas emuladas no mesmo hospedeiro: um pedido ao outro
dispositivo leva de **0,7 a 2 s** — o aperto domina. O prazo da conversa
(8 s) fica com folga de 4× sobre o pior medido; a espera de quem pede
(10 s), com folga maior. O kernel de produção cresceu 300 672 bytes
carregáveis no x86 e 185 460 no ARM, contra a malha.
