# A malha do Duke

A malha é a fundação do ecossistema Duke: o lugar por onde as aplicações
e os dispositivos cooperam como partes de um ambiente só. Este documento
descreve o **primeiro marco**, o que está implementado e testado:
**aplicação A → malha → aplicação B**, numa máquina, entre os programas de
um mesmo titular. A outra metade do marco, **dispositivo A → malha →
dispositivo B** — a malha de um Duke levada à de outro, relacionado a uma
pessoa desta máquina —, é o estágio 1 de B-E1/B-E2, descrito em
[ENLACE.md](ENLACE.md).

## O princípio

A malha **não é uma autoridade**. Ela não decide nada: encontra candidatos,
leva textos e lembra estados. Quem decide é o gate, pela política, como em
todo o resto do sistema:

```
pessoa ou agente → titular → processo e programa → intenção (capacidade)
      → política → gate → operação na malha → auditoria
```

Nenhuma operação da malha passa ao lado do gate, e nenhuma autoridade
viaja com uma entrega: quem recebe ganha um texto, e o que faz com ele é
decidido pelo papel dele, pedido a pedido.

## Os conceitos

- **Intenção** — o que um programa quer que seja feito, ou o que ele sabe
  fazer: `imagem.compartilhar`, `pdf.anotar`. A forma é fechada:
  `<espaço>.<nome>[.<nome>…]`, partes de minúsculas, dígitos e `_`, cada
  uma começando por letra, até 48 bytes. Sem curinga.
- **Endpoint** — um processo oferecendo uma intenção. É do processo: só
  ele o abre, lê o que chega por ele, confirma e o fecha, e ele some com o
  processo. Um processo abre até 4; um titular, até 16.
- **Entrega** — um texto opaco (até 512 bytes) levado a um endpoint, com
  estados e versões: `pending` ao entrar, `delivered` na primeira leitura
  (ler não consome), `acked` na confirmação — com uma resposta opcional, de
  até 512 bytes, para quem mandou —, `canceled` se quem mandou desiste antes
  da leitura, `voided` quando o endpoint acaba ou o titular é revogado,
  `expired` pelo prazo (60 s por omissão, até 10 min).
- **Titular** — por quem o programa age: a pessoa (pelo identificador do
  registro, não pela sessão), o agente (pela chave), a serial ou o sistema.
  Uma entrega só vai de um programa a outro do **mesmo** titular. Entre
  titulares, a ferramenta continua sendo a mensagem, com o papel do
  destinatário como recurso.

## A identidade de um programa

Um endpoint e uma entrega carregam o programa que o kernel carregou — o
nome do manifesto, o resumo BLAKE2s da imagem e, para o código de fora da
imagem, a chave do editor que o selou —, e não o que o programa diz ser.
Dois programas que declaram o mesmo nome aparecem como dois candidatos com
resumos diferentes; quem procura escolhe pelo que eles **são**. A suíte
prova isso com o `impostor`, que declara o nome `correio`.

## As permissões e a política

Duas permissões novas, sensíveis e não administrativas, com a intenção
como recurso enumerado:

- `fabric.offer` — oferecer uma intenção, ler o que chega e confirmar;
- `fabric.send` — procurar quem oferece, mandar, consultar e cancelar.

```
papel operador ... fabric.offer fabric.send
recurso operador fabric.offer intencao:imagem.compartilhar intencao:pdf.anotar
recurso operador fabric.send intencao:imagem.compartilhar intencao:pdf.anotar
```

O alcance é a lista exata — `intencao:imagem.*` é recusado na leitura da
política. A permissão efetiva de um programa é a de sempre: o papel de
quem o lançou ∩ o manifesto dele. Na política padrão, o operador, o
sistema e o teto do administrador têm as duas, para as duas intenções de
exemplo; o observador não tem nenhuma. A política de produção de exemplo
(`docs/exemplos/producao/politica`) traz as mesmas linhas, para trocar
pelas intenções dos programas da imagem.

## O caminho de um pedido

Os oito comandos — `fabric.offer`, `fabric.withdraw`, `fabric.discover`,
`fabric.send`, `fabric.recv`, `fabric.ack`, `fabric.cancel`,
`fabric.status` — estão no registro, com os mesmos parâmetros para um
agente pelo canal, uma pessoa pelo interpretador e um programa pela
interface nativa.

1. **O registro** confere a forma da intenção (`INVALID_ARGUMENT`).
2. **O gate** decide `intencao:<nome>`:
   - a do pedido, nos comandos que a recebem (`offer`, `discover`, `send`);
   - a do endpoint ou da entrega que o pedido nomeia, nos outros,
     **resolvida para quem pede**: o id de outro titular, de outro
     processo, um forjado ou um que não existe não resolve, e quem tem a
     permissão ouve `DENY_RESOURCE` — sem saber qual dos quatro. Quem não
     tem a permissão ouve `DENY_PERMISSION` antes de qualquer resolução.
   - `fabric.offer`, `fabric.withdraw`, `fabric.recv` e `fabric.ack` só de
     um processo: de outro chamador, `DENY_PERMISSION`.
3. **A operação** roda com a ordem das gravações na mão e decide de novo
   (`reconfirmar`): uma revogação, uma política nova ou uma contenção que
   passou entre o gate e a operação a recusa — e a revogação que vem
   depois a encontra inteira, e anula o que ela fez. A malha confere ainda
   que age sobre a intenção que o gate decidiu.
4. **O destino ainda recebe?** Uma entrega só vai a um endpoint cujo dono
   está vivo e exerceria agora `fabric.offer` sobre a intenção — o papel de
   quem o lançou, o manifesto, a contenção, a sessão da pessoa, a confiança
   no editor. A política que tira a permissão do dono, ou o dono isolado,
   o tira da descoberta e recusa a entrega, até ele voltar a receber.

## A descoberta e a privacidade

- **Quem pode descobrir:** quem tem `fabric.send` para aquela intenção.
- **O que descobre:** só os endpoints do **próprio titular** que oferecem
  exatamente aquela intenção e cujo dono ainda receberia. Os de outro
  titular não existem para ele.
- **Quais metadados:** o id do endpoint, o nome do manifesto, o resumo da
  imagem, o editor (se o código veio de fora da imagem) e desde quando.
  Nada de pessoa, sessão, caminho, arquivo ou rede.
- **Quando:** enquanto o endpoint existe e o dono vive e recebe.

Descobrir não concede nada: cada entrega é decidida de novo.

## Replay, duplicata e cotas

Cada envio traz um `nonce` que só cresce no canal de quem manda — o
processo, a sessão. O mesmo nonce com o mesmo conteúdo é o reenvio, e
devolve o mesmo id sem criar nada; um nonce velho, ou o mesmo com outro
conteúdo, é `DENY_REPLAY`. Um destino que não existe não gasta nonce. As
cotas são da tabela: 32 entregas vivas por canal de quem manda, 32
esperando por endpoint, 128 na malha, 64 endpoints — cada recusa é
`DENY_POLICY` com o motivo. A taxa do papel vale para cada pedido, como em
todo comando.

## Revogação e fim

- **A chave de um agente revogada, ou a pessoa revogada:** os endpoints
  dos programas do titular fecham e as entregas vivas dele são anuladas,
  na hora, cada uma gravada. A mesma chave registrada de novo não recupera
  nada: as anuladas continuam anuladas.
- **O processo que acaba** — saída, término, falha: os endpoints dele
  fecham e o que esperava neles é anulado; o que ele mandou continua.
- **A sessão que acaba:** a janela de nonces dela sai; os programas da
  pessoa que saiu não pedem mais nada, e o dono que não receberia some da
  descoberta.

Não há canal velho com acesso indefinido: cada pedido é decidido de novo.

## A espera

`fabric.recv` com `wait` (até 10 s) sem nada novo suspende o pedido no
endpoint, pelo mesmo mecanismo da espera de rede, e acaba quando uma
entrega chega, o endpoint fecha ou o prazo vence. Acordado, o pedido é
executado de novo, inteiro, pelo gate. Uma espera por endpoint.

## Energia

Com um reinício ou um desligamento a caminho, nada novo nasce:
`fabric.offer` e `fabric.send` são `CONFLICT` ("a maquina esta
reiniciando ou desligando"); ler, confirmar e consultar continuam.

## Auditoria e proveniência

Pela auditoria de sempre — nenhuma nova. Cada pedido grava a decisão do
gate, com o titular, o papel, o processo e o programa (nome e resumo), e o
recurso `intencao:<nome>`. Cada execução grava o que fez, ligada pelo
número da decisão que a autorizou (`; decisao N`). O detalhe de um registro
tem teto (96 bytes), e o de uma execução já leva o processo e o programa na
frente e a decisão no fim; por isso os ids vão no **recurso** — que tem
teto maior e separa vários recursos por ` ; `, como os de qualquer pedido
—, e o detalhe diz só o que aconteceu. A suíte confere que nenhum registro
da malha chega ao teto: nada é cortado.

| método | recurso | o que diz |
|---|---|---|
| `fabric.offer` | `endpoint:<id> ; intencao:<nome>` | aberto, e a versão da política |
| `fabric.send` | `entrega:<id> ; endpoint:<id>` | aceita, pendente, e a versão da política — ou o reenvio |
| `fabric.recv` | `entrega:<id>` | entregue, com a versão |
| `fabric.ack` | `entrega:<id>` | confirmada, com a versão |
| `fabric.cancel` | `entrega:<id>` | cancelada, com a versão |
| `fabric.withdraw` | `endpoint:<id>` | fechado — por quem o abriu, pela revogação (em nome do kernel), pelo fim do processo |
| `fabric.void` | `entrega:<id>` | anulada, e por quê (em nome do kernel, quando não foi pedido) |
| `fabric.expire` | `entrega:<id>` | o prazo venceu (em nome do kernel) |

Os registros formam uma cadeia de ids: a entrega aponta o endpoint de
destino; o registro da oferta desse endpoint diz o processo e o programa
dono; o processo e o programa de quem mandou estão no próprio registro da
entrega; a intenção e o papel, na decisão que ele cita. Juntos, respondem:
quem iniciou, por qual aplicação, nesta máquina, com que capacidade, por
qual decisão e qual versão da política, para qual destino, e com que
resultado. **Nunca o corpo nem a resposta** — a suíte confere.

## Volátil

A malha vive na memória, como um canal de eventos: um boot a perde. A
época, sorteada no primeiro uso, entra em cada id — `<época>:<n>` —, e um
id de outro boot não é de nada. Não há journal da malha, e ela não toca o
armazém, a cópia de segurança nem a identidade: o B5 continua como foi
fechado.

## Como um programa usa

```rust
use programas::malha;

// Quem atende:
let endpoint = malha::oferecer("imagem.compartilhar")?;
for e in malha::receber(&endpoint, None, 10_000)? {
    malha::confirmar(&e.id, Some("guardada"))?;
}

// Quem manda:
let candidatos = malha::descobrir("imagem.compartilhar")?;
let id = malha::enviar(&candidatos[0].endpoint, "imagem.compartilhar", "/foto.png", 1)?;
let (estado, resposta) = malha::estado(&id)?;
```

O manifesto declara o que o programa exerce: `fabric.offer` para atender,
`fabric.send` para mandar.

## O que fica de fora

- **Dispositivo → malha → dispositivo** está em [ENLACE.md](ENLACE.md): o
  dispositivo como principal próprio, a chave do Duke dele no Noise IK, a
  relação com uma pessoa daqui, a autoridade composta no destino. O que
  ainda fica de fora dele — pareamento, descoberta, propagação da
  revogação, armazenamento-e-envio — está lá.
- **Handoff, streams, recursos remotos, presença.** Os próximos marcos.
- **Entre titulares.** De propósito: a mensagem já é esse caminho.
- **Persistência.** A malha é volátil; uma entrega não sobrevive ao boot.

## Testes

- **Hospedeiro** (`politica`): a forma da intenção, a tabela inteira — as
  cotas, o mesmo titular, a intenção oferecida, replay e duplicata, os
  estados, o prazo, a revogação e a morte, quem cancela e quem confirma —
  e a tabela coerente sob 4000 operações sorteadas; a permissão e a linha
  `recurso … intencao:` da política.
- **Suíte** (x86 e ARM), com programas de verdade — `correio`, `fotos` e o
  `impostor` —: a entrega de ponta a ponta (com cada passo gravado e
  nenhum registro cortado), o impostor, só o mesmo titular, o gate em cada
  passo, a revogação, a decisão no meio da operação, a espera e o fim do
  processo, o desligamento a caminho, envios, leituras e a revogação ao
  mesmo tempo, o prazo que vence sozinho (o coletor tira a entrega e grava
  `fabric.expire`, sem o corpo; quem mandou vê `expired`, e o dono não a lê
  mais), o nonce que saiu da janela dos 32 recentes (replay, com o corpo de
  antes ou outro), e o custo de uma entrega pelo gate inteiro.
- **Mutações**: trinta e quatro, uma de cada vez — o gate, a revogação, a
  conta pura, a proveniência, a espera, o desligamento, o registro, a
  política e o prazo pelo coletor —, e as trinta e quatro reprovam; a
  tabela, com o que pega cada uma, está no README ("As mutações da
  malha").
