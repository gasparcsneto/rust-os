# O SDK da malha (DN-3)

Este documento descreve o **DN-3**, o que está implementado e testado: o
que um programa precisa para usar a malha — as entregas
([MALHA.md](MALHA.md)), os fluxos ([FLUXOS.md](FLUXOS.md)), locais e entre
Dukes ([ENLACE.md](ENLACE.md)) — **sem fios, sem esperas presas a um
objeto, e escrito fora deste repositório**. São duas decisões novas,
aprovadas antes da implementação, e o que se constrói sobre elas:

- **DS-1 — o aviso da malha no canal de eventos.** Um processo pede, no
  mesmo pedido que cria ou aceita um objeto da malha, que o kernel o avise
  no canal de eventos dele quando o objeto ficar pronto. O aviso **só
  sinaliza prontidão**: não concede nada, não leva conteúdo, e não
  substitui nenhuma decisão do gate.
- **DS-2 — o contrato público da interface nativa v2.** O que um programa
  de fora do repositório pode usar é uma lista explícita, versionada e
  conferida contra as fontes a cada commit: `sdk/contrato.txt`, e
  `native_interface: 2` no `system.info`.

E, sobre as duas:

- o runtime: [`programas::laco`](../programas/src/laco.rs) (a espera
  única), as variantes com aviso de [`programas::fluxo`](../programas/src/fluxo.rs)
  e [`programas::malha`](../programas/src/malha.rs), e
  [`programas::quadro`](../programas/src/quadro.rs) (mensagens sobre um
  fluxo);
- as ferramentas: `cargo xtask selar`, `cargo xtask sdk-conferir` e
  `cargo xtask sdk-fora`;
- o modelo de projeto, [`sdk/modelo/`](../sdk/modelo), e três exemplos:
  `eco-malha`, `conversa` e `copiador`.

Nada disso muda quem decide. O caminho de um programa que usa o SDK é o
de sempre — cada passo um pedido ao gate, com a autoridade de quem o
lançou, o manifesto dele e a política:

```
aviso (só: este objeto, esta prontidão) → o programa acorda → pedido ao gate → operação
```

e nunca `aviso → operação`. O caso da política que tira a permissão entre
o aviso e a leitura prova (NS15) — a leitura avisada é recusada, e a
decisão gravada é a recusa do gate —, e a mutação N16 o confere; o da
revogação da pessoa (NS11) mostra que a leitura não traz o dado.

## Por que

Um processo do Duke tem um fio só, e um pedido que espera espera **um**
objeto. Um programa parado num `stream.read` não vê a tecla, o outro
fluxo, nem o pedido novo no endpoint. Antes do DN-3, servir dois clientes
exigia girar por todos com esperas curtas — gastando o orçamento do plano
de dados em pedidos vazios — ou não servir. E quem quisesse escrever um
programa fora do repositório não tinha o que copiar, nem a lista do que
pode usar sem que mude.

## O contrato v2 (DS-2)

[`sdk/contrato.txt`](../sdk/contrato.txt) é a lista conferida do contrato:

| Lista | O que é | Onde mora |
|---|---|---|
| `chamada` | as 20 chamadas de mecanismo, `SAIR` a `PEDIR_COM_ANEXO` | `protocolo::usuario::numero` |
| `erro` | os 20 erros das chamadas | `protocolo::usuario::erro` |
| `evento` | os 9 tipos de evento, `MALHA` entre eles | `protocolo::usuario::evento::tipo` |
| `malha` | os tipos de objeto e os bits do aviso | `protocolo::usuario::evento::malha` |
| `nativo` | os tetos do envelope: o pedido (4096) e o anexo (61440) | `protocolo::usuario::nativo` |
| `codigo` | os 15 códigos de decisão, `ALLOW` a `DENY_CREDENTIAL` | `politica::Codigo` |
| `comando`/`param` | os 15 comandos da malha (`fabric.*` e `stream.*`), cada parâmetro com o tipo e a obrigatoriedade | o registro do kernel |

A forma binária do programa — o ELF dos dois alvos, o `usuario.ld`, a
entrada `principal` e a nota `Duke` com `duke-manifesto 1` — também é
contrato, sem mudança de formato; ela é conferida na carga de cada
programa.

**As regras.** Dentro da versão o contrato só cresce: um comando novo,
um parâmetro opcional novo, um campo novo num resultado, um tipo de evento
novo, um bit novo, um código novo. Um nome nunca muda de sentido. O que o
kernel não conhece ele **recusa**, nunca ignora: o método desconhecido é o
erro −32601 do JSON-RPC, e o parâmetro desconhecido ou de outro tipo, o
−32602 com o nome dele (a auditoria os grava como `INVALID_ARGUMENT`); a
chamada de mecanismo desconhecida, `NUMERO_INVALIDO`; a permissão
desconhecida no manifesto recusa o programa na carga. O programa ignora,
no que recebe, o que não conhece — um bit do aviso que esta versão do
runtime não sabe não muda nenhuma resposta de
[`Prontidao`](../programas/src/laco.rs). Remover é só numa versão maior,
por decisão própria, e o removido é recusado. Um kernel tem uma versão
viva.

**O que não é contrato.** O resto do registro — fora `fabric.*` e
`stream.*` — continua descrito pelo `agent.describe`, sem promessa, até
uma decisão o pôr no contrato; e também não são contrato o texto do
detalhe da auditoria, os tempos, as cotas e os tetos de
[As cotas](#as-cotas) — fora os dois do envelope —, os programas da imagem,
a política, e os módulos do runtime que este documento não descreve.
`fluxo::padrao` e `fluxo::Resumo` são da bancada: o modelo os usa só para
conferir os bytes da troca que a bancada mede, e um programa não precisa
deles.

**A conferência (NI01–NI03).** O `cargo xtask invariantes` lê a lista e
as fontes e reprova:

- o que a lista tem e a fonte não tem, ou tem com outro valor, outro
  tipo, outra obrigatoriedade — tirar, renomear ou mudar o sentido de um
  nome do contrato é quebrá-lo;
- o que a fonte tem, dentro do contrato, e a lista não — crescer é decisão
  revisada, e não acaso;
- a versão da lista diferente de `nativo::VERSAO`;
- o tipo `MALHA` publicado fora de `kernel/src/aviso.rs`, ou montado sem a
  conta de `politica::aviso`, e qualquer leitura de conteúdo — o buffer de
  um fluxo, o corpo de uma entrega — no módulo do aviso;
- o `usuario.ld` e as opções de compilação do modelo diferentes das dos
  programas da imagem.

Na suíte, o `agent.describe` — o que um agente lê para descobrir o canal —
confere os comandos da malha contra a mesma lista (NS29), e o
`system.info` diz `native_interface: 2` (NS30).

## Escrever um programa

Um programa do Duke é `no_std`, sem `main`: o runtime chama a função
`principal`, e o que ela devolve é o código de saída. O manifesto — o nome
e as permissões que o programa pretende exercer — vai numa nota do
executável:

```rust
#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("meu-programa", "fabric.offer", "fabric.stream");

#[unsafe(no_mangle)]
fn principal() -> i64 {
    programas::escreverln!("ola");
    0
}
```

O processo exerce a **interseção** do papel de quem o lançou com o que o
manifesto declara. Para a malha, quem administra enumera na política, para
o papel de quem roda o programa:

- `fabric.offer` sobre a intenção (`intencao:<nome>`), para oferecer;
- `fabric.stream` sobre a intenção, para abrir e aceitar fluxos;
- `fabric.send` sobre a intenção, para **descobrir** quem a oferece
  (`fabric.discover`) e para mandar entregas — quem só serve não precisa
  dela, quem procura o outro precisa;
- `fabric.remote` sobre o dispositivo, para falar com outro Duke;
- e, para um programa de fora da imagem, a confiança no editor que o
  selou.

Sem curinga: a intenção é enumerada, uma a uma. O `notify` não pede
permissão nenhuma — ele vai no pedido que a permissão já decide.

## O laço

[`Laco`](../programas/src/laco.rs) é o canal de eventos do processo — a
única espera dele. O programa escuta um canal só dele (`laco-<id>`), passa
o descritor do canal como `notify` nos pedidos que criam ou aceitam objetos
da malha, e dorme em `Laco::esperar`:

```rust
use programas::fluxo;
use programas::laco::{Acontecimento, Laco};
use programas::malha;

let mut laco = Laco::novo()?;
let endpoint = malha::oferecer_avisando("minha.intencao", &laco)?;
loop {
    for a in laco.esperar()? {
        match a {
            Acontecimento::Endpoint { prontidao, .. } => {
                if prontidao.entrega() { /* malha::receber */ }
                while let Some((f, origem)) = fluxo::aceitar_avisando(&endpoint, &laco)? {
                    /* guardar f pelo número: f.numero() */
                }
            }
            Acontecimento::Fluxo { numero, prontidao } => { /* ler e escrever o fluxo `numero` */ }
            Acontecimento::Evento(e) => { /* a janela, o pseudo-terminal, ENCERRAR */ }
        }
    }
}
```

A janela manda a entrada para o mesmo canal (`Janela` com a operação
`ENTRADA`), e o pseudo-terminal também: um processo, uma espera. O nome
`laco-<id>` é previsível: se outro processo já o tomou, `Laco::novo` tenta
`laco-<id>-1`, `laco-<id>-2`… — quem toma o nome antes não impede o
programa de subir (NS37).

### O que o aviso diz

Um evento `MALHA` (tipo 9) tem três campos, e só três:

| Campo | O que é |
|---|---|
| `a` | o tipo do objeto: `ENDPOINT` (1) ou `PONTA` (2) — a ponta de um fluxo |
| `b` | o número do id do objeto — o `<n>` de `<época>:<n>`, o mesmo de `Fluxo::numero` |
| `c` | os bits de prontidão |

| Bit | Objeto | Quer dizer |
|---|---|---|
| `LEGIVEL` (1) | ponta | há o que ler: bytes, ou o fim do sentido |
| `GRAVAVEL` (2) | ponta | há espaço — só para quem esbarrou no cheio, e para quem abriu, na abertura |
| `FIM` (4) | os dois | o objeto acabou: a operação seguinte ouve o motivo |
| `PEDIDO` (8) | endpoint | há um pedido de fluxo esperando o aceite |
| `ENTREGA` (16) | endpoint | há entregas ainda não recebidas |

Nenhum byte do fluxo, nenhum corpo de entrega, nenhum motivo, nenhum quem.

### A regra: depois de cada aviso, opere

O aviso é na **borda**, e a operação do dono o **rearma**:

- um objeto tem **no máximo um aviso não consumido**. Enquanto ele não é
  consumido, nada mais desse objeto vira aviso novo — o `FIM`, no máximo,
  junta-se a ele, se ele ainda espera na fila (abaixo);
- **a operação do dono sobre o objeto consome o aviso** — ler, escrever,
  aceitar, receber, ver o estado —, e o nível de agora é reavaliado: o que
  ainda está pronto avisa de novo;
- por isso, a cada aviso, o programa **opera** sobre o objeto até não
  haver mais nada a fazer agora: lê até vir vazio, escreve até não caber,
  aceita até não haver pedido, recebe as entregas. Um aviso ignorado é um
  objeto mudo — e a operação que o consumir, mesmo tarde, ouve o que
  aconteceu, o fim inclusive;
- `GRAVAVEL` é só para quem esbarrou no cheio — a escrita que não coube
  inteira pede o próximo espaço —, e para quem abriu o fluxo, na
  abertura. Quem nunca esbarrou não é acordado por espaço;
- `FIM` sai uma vez: como aviso novo, só com o aviso anterior consumido.
  Depois da operação do dono que ouviu o fim, nada mais é publicado sobre
  o objeto, e a designação sai. O objeto que acaba com um aviso ainda não
  consumido não avisa o fim de novo: o `FIM` se junta ao evento desse
  aviso, se ele ainda espera na fila — o dono lê os dois juntos —, e a
  designação sai ali; se o dono já o tirou da fila, o fim espera a
  operação dele, a que consome o aviso — e, se ela não ouviu o fim (a
  leitura do último dado, que acabou com o fluxo, ou a operação recusada),
  o `FIM` sai em seguida, uma vez (NS03, NS32, NS40). A conta de outro
  núcleo que perguntou o nível antes da operação do dono não publica
  depois dela: a operação muda a geração da designação, e a conta dela,
  com o nível de depois, é que decide — o `FIM` que a operação ouviu, o
  dado que ela leu, não voltam como aviso (NS48);
- a operação do dono **que não passa** — recusada pelo gate (a política,
  a taxa, a contenção), pela reconfirmação dentro da decisão, ou pelo
  próprio comando (a cota de fluxos cheia, o estado do objeto) — também
  consome o aviso: senão o objeto ficaria mudo. Mas o que ela encontrou
  pronto não avisa de novo na hora — voltaria a ser recusado, num giro de
  aviso, recusa e aviso —: avisa pelo coletor um segundo depois da recusa,
  e o dobro a cada recusa seguida, até um minuto (a recusa seguida não
  adia o rearme já marcado), e até lá só o que é **novo** no objeto avisa —
  um bit que o dono ouviria e que não estava pronto na recusa (o espaço
  que ele não quer não conta, NH19): a entrega que chega ao endpoint
  cujo aceite foi recusado, o fim. A mudança de outro objeto (uma entrega
  a outro endpoint, o fim de um fluxo alheio) e o mesmo bit de novo (um
  segundo pedido) não trazem de volta o que foi recusado, e o aviso não
  diz a ninguém quando outro mexeu na malha — também quando as mudanças
  são tantas que as marcas do kernel transbordam: mais de 64 objetos
  distintos marcados entre duas passadas (o objeto que muda de novo antes
  da passada não conta outra vez), de qualquer processo, de qualquer
  pessoa. A passada que acha o transbordo avalia todas as designações com
  a mesma conta e o mesmo filtro, e o pedido que a recusa espaçou só
  avisa no rearme (NS54). A operação que passa zera a
  conta (NS33, NS38, NS39). O fim de um fluxo dá uma **vaga** na cota dos
  processos em que ele contava — o de quem abriu, sempre; o de quem aceitou,
  se ele foi aceito: o pedido que acaba sem aceite não contava na cota do
  dono do endpoint —: o dono que não pôde aceitar por falta de vaga é
  avisado do pedido assim que ela abre, uma vez — também quando ela abre no
  meio do aceite recusado, ou com um aviso de antes dela ainda não
  consumido: a recusa que vem antes de o aviso da vaga sair não espaça, e
  ele sai logo depois dela (NS38, NS39, NS43), também se o rearme da
  recusa anterior passou no meio, com o aviso de antes ainda não
  consumido — o rearme que não publica não apaga a marca da vaga (NS53).
  E a vaga não se perde quando as marcas transbordam: a marca dela — uma
  por processo — fica à parte das dos objetos, fora do teto delas, e o
  pedido avisa na hora, e não só no rearme (NS52); o transbordo, ele
  mesmo, não conta ninguém como talvez com uma vaga. A recusa que responde ao
  aviso da vaga — com a vaga já tomada pelo próprio dono, que abriu ou
  aceitou outro fluxo — espaça como as outras: a mesma vaga não avisa duas
  vezes (NS50). E a recusa no meio da qual o aviso da vaga já saiu — o
  pedido estava sem aviso pendente — o consome e espaça também; o evento
  fica no canal, e o dono o lê, uma vez (NS51). O objeto que já acabou não
  espera o rearme: depois da operação recusada, o `FIM` sai na hora
  (NS40). E a conta da recusa é refeita depois de ela consumir o aviso,
  sempre: o que mudou depois de ela perguntar o nível — o objeto que
  acabou, um bit novo — também não espera o rearme (NS45);
- a operação que passa **sem mudar nada** — o aceite sem pedido na fila, a
  recepção sem entrega nova — consome o aviso sem desfazer o rearme
  espaçado de uma recusa; e a recepção que não tira nenhuma entrega da
  pendência, com pendente ainda lá (a que relê as já lidas, sem `after`),
  conta como a que não passa (NS41);
- **um aviso de cada objeto no canal**: a operação do dono consome o aviso
  mesmo que o evento ainda esteja na fila do canal — o programa que lê
  várias vezes seguidas, sem voltar ao laço, rearma a cada leitura. O
  aviso seguinte do mesmo objeto, com o anterior ainda na fila, **junta-se**
  a ele (os bits somados) em vez de ocupar outro lugar: o canal nunca tem
  dois eventos do mesmo objeto, e um fluxo agitado não enche o canal de
  avisos velhos (NS01b).

O endpoint avisa `ENTREGA` enquanto houver entrega **pendente** — que
nenhuma recepção leu. Quem usa entregas recebe com `after` — a página
seguinte, depois da última lida — até vir vazia, e confirma
(`malha::confirmar`) o que tratou: a recepção sem `after` relê as já
lidas, que ficam até a confirmação ou o prazo, e não alcança as seguintes.
O programa que oferece com o aviso e não usa entregas chama
`malha::descartar_entregas` quando o bit vem: ela recebe página a página e
confirma cada uma, e o aviso se cala (NS41).

### O canal cheio, a morte, a troca de imagem

- O canal guarda 64 eventos. Com ele cheio, o aviso fica **devido** e o
  coletor o entrega depois, sem perder o objeto nem duplicar o aviso. O
  fim de um objeto que acabou com o canal cheio fica devido. Ele e o fim
  na espera da operação do dono são as únicas designações sem objeto vivo,
  e um processo guarda no máximo 8 delas; passado disso, cai a de menor
  chave — os endpoints antes das pontas e, entre as do mesmo tipo, a mais
  antiga (ver [Limites conhecidos](#limites-conhecidos)) —, contada em
  `dropped`: um processo que não lê o canal, ou que lê e não opera, não
  acumula objetos que já acabaram (NS32).
- O canal que ninguém mais escuta — o processo fechou o descritor, ou
  morreu — larga as designações dele.
- A troca de imagem (`exec`) larga as designações **antes** do resto, e
  os avisos que ainda esperavam na fila dos canais do processo saem com
  elas: a imagem nova herda os descritores, e não ouve os avisos da
  anterior (NS17, NS36). Os endpoints persistem, como sempre persistiram
  (a malha os mantém na troca de imagem); a imagem nova oferece com o
  aviso de novo, se quiser. Os canais que a imagem anterior escutava
  continuam escutados pelo processo — o mesmo fio — e contam no teto dos
  dois: com os dois ocupados, a imagem nova que quer o seu laço fecha antes
  os que não vai usar, ou o `Laco::novo` ouve `OCUPADO` em todos os nomes.
  Os descritores herdados de um `fork` — como os que o Terminal fecha ao
  entrar — não contam: o filho não é ouvinte deles.
- O `fork` não passa designação nenhuma: o filho não é dono de pontas nem
  de endpoints, e um descritor herdado não o faz ouvinte do canal — o
  `notify` com ele é recusado.

### O que é recusado

O `notify` é conferido dentro da decisão do próprio comando: tem de ser um
descritor de canal de eventos **deste processo**, de que ele é o ouvinte.
Senão o pedido inteiro é recusado com `INVALID_ARGUMENT` e o motivo
`notify nao e canal deste processo` — o objeto não é criado nem aceito, e
nada é designado. Um `notify` que não é inteiro não negativo nem chega à
decisão: o registro o recusa pela forma (−32602, com o nome), e o comando
que não tem `notify` o recusa pelo nome (NS09). Só um processo designa: só
um processo oferece, abre e aceita, e o pedido de uma pessoa ou de um
agente é recusado como sempre, com o mesmo código com ou sem `notify`
(NS14).

### Auditoria e medidas

O aviso não tem registro próprio na auditoria: a designação está no
registro de execução do comando que a pediu, na mesma cadeia, com o nome
do canal — só com letras e dígitos ASCII e `-_.:/`, o resto vira `_`: o
nome é texto do processo, e não pode imitar a citação da decisão (NS35)
—, e cada operação depois do aviso está no registro dela. As medidas vão ao
`security.metrics`, em `mesh_notices`: as designações guardadas
(`designations`) — também as dos objetos que já acabaram, no teto do
processo —, os avisos
publicados (`published`), os juntados a um do mesmo objeto ainda na fila
(`merged`), as mudanças que não avisaram porque já havia um aviso não
consumido (`coalesced`), os que acharam o canal cheio (`full_channel`) e
os entregues depois (`delivered_later`), as designações largadas com o
canal (`dropped`), os `notify` recusados (`refused`) e a latência do aviso
publicado até a operação do dono que o consome (`to_operation_samples`,
`to_operation_avg_ns`, `to_operation_max_ns`). `dropped` conta também as
designações acabadas que passaram do teto do processo.

## As entregas e os fluxos

| Função | Comando | O aviso |
|---|---|---|
| `malha::oferecer_avisando` | `fabric.offer` com `notify` | o endpoint: `PEDIDO`, `ENTREGA`, `FIM` |
| `fluxo::abrir_avisando` | `stream.open` com `notify` | a ponta de quem abriu: `GRAVAVEL` na abertura, depois `LEGIVEL`, `GRAVAVEL`, `FIM` |
| `fluxo::abrir_no_par_avisando` | `stream.open` com `device` e `notify` | o mesmo, deste Duke: o de lá avisa o programa de lá |
| `fluxo::aceitar_avisando` | `stream.accept` com `notify` | a ponta aceita: `LEGIVEL`, `GRAVAVEL`, `FIM` |

Os pedidos "agora" — `Fluxo::ler_agora`, `Fluxo::escrever_agora` e
`aceitar_avisando` — não esperam dado, espaço nem pedido. Os dois de dados
levam a espera mínima do plano de dados (1 ms), para o caminho da
auditoria cheio poder segurá-los em vez de cobrar a taxa; o aceite, do
plano de controle, vai sem `wait`. O que não coube na escrita espera numa
[`EscritaPendente`](../programas/src/fluxo.rs), que escoa quando o
`GRAVAVEL` vem. As variantes com espera do DN-2 continuam valendo, e um
mesmo processo pode ter um fluxo com o aviso e outro sem.

**Quem retira ou fecha.** Quem retira um endpoint que designou não é
avisado do fim dele (salvo a corrida estreita de [Limites
conhecidos](#limites-conhecidos)), e quem fecha um fluxo não é avisado de
nada mais: sabem, porque fizeram. O fecho que a reconfirmação recusa deixa
o fluxo vivo, e a designação com ele (NS34).

**O fim e o fecho.** `Fluxo::terminar` termina o sentido daqui: o outro
lado lê o resto e o fim (`LEGIVEL`). Quando o fluxo acabou de vez para o
dono — o outro lado fechou (lido o que ele mandou), foi revogado, o
processo dele morreu, o
dispositivo foi suspenso ou esquecido —, a ponta avisa `FIM`, e a próxima
operação ouve `CONFLICT` com o motivo (`fechado pela ponta`, `revogado`,
`o dispositivo foi suspenso`…). A escrita de quem ficou, com o sentido
dela fechado pelo par, ouve `CONFLICT` — e a designação fica, enquanto
ainda há o que ler do par: o resto e o fim ainda avisam (NS42); se o fluxo
acaba logo depois dela, o fim que ela não ouviu é avisado (NS46). Quem
desiste de um fluxo, ou acabou com ele, o fecha (`Fluxo::fechar`) antes de
largar o estado — o que já escreveu segue legível para o outro até o fim
do sentido —; senão ele fica vivo, contado nas cotas, até vencer a
inatividade. Os exemplos fecham: o `eco-malha` o fluxo largado pelo
cliente (NS44), e o `copiador` o de cada cópia, dos dois lados (NS47).

**Entre Dukes.** O aviso é sempre local: o Duke daqui avisa o programa
daqui, pelo crédito e pelos dados que chegam do par; nada do aviso
atravessa o enlace, e o protocolo do fluxo entre Dukes não mudou.

**Mensagens.** O fluxo leva bytes; [`programas::quadro`](../programas/src/quadro.rs)
delimita mensagens sobre eles — o tamanho em quatro bytes, e o corpo —,
com `quadro::juntar` (para a saída pendente) e `quadro::Entrada` (que junta
os pedaços até a mensagem inteira, com o teto de quem lê). O conteúdo
continua sendo entrada não confiável.

## Os padrões

- **O servidor de vários clientes** —
  [`eco-malha`](../programas/src/bin/eco-malha.rs). Um processo, uma
  espera: o `PEDIDO` aceita todos os pedidos da fila, cada fluxo aceito é
  um cliente, e o aviso de cada um faz esse cliente andar — escrever o que
  esperava, ler o que chegou. Ninguém espera ninguém. NS26: três clientes
  ao mesmo tempo, todos os bytes de volta, na ordem.
- **Os dois sentidos ao mesmo tempo** — escrever o que cabe, ler o que há,
  e dormir no laço. O estilo bloqueante (escrever tudo, depois ler) empaca
  quando os dois lados escrevem mais que um buffer: NS06 mostra o laço
  passando e o bloqueante vencendo o prazo.
- **A janela e o fluxo** — [`conversa`](../programas/src/bin/conversa.rs).
  A entrada da janela e os avisos chegam no mesmo canal; a primeira
  mensagem abre o fluxo, e ela espera o aviso da abertura antes de
  escrever. NS27.
- **Mensagens sobre um fluxo** —
  [`copiador`](../programas/src/bin/copiador.rs). Um arquivo do armazém
  mandado a outro copiador, que o grava pelo `fs.write` **dele**: o fluxo
  não dá escrita nenhuma. Os dois fecham o fluxo quando a cópia acaba.
  NS47.
- **O modelo** — [`sdk/modelo`](../sdk/modelo/src/main.rs): o eco com o
  laço, e o cliente de outro modelo quando o armazém tem o pedido. NS28.

## As falhas e os motivos

| O que | O que o programa vê |
|---|---|
| `notify` que não é canal deste processo | `INVALID_ARGUMENT`, `notify nao e canal deste processo`; nada criado |
| a política tira a permissão, ou a pessoa é revogada, entre o aviso e a operação | a operação é recusada pelo gate, com o código dela (NS15), ou ouve o fim (NS11); o dado não sai |
| o outro lado fechou | `LEGIVEL` enquanto há o que ler — o resto e o fim do sentido dele —; depois, `FIM` (ou `GRAVAVEL`, a quem esbarrou no cheio); a operação seguinte, `CONFLICT` `fechado pela ponta` (NS03) |
| o processo do outro lado morreu | `FIM`; `CONFLICT` `o processo acabou` |
| o dispositivo suspenso, esquecido ou revogado | `FIM`; `CONFLICT` com o motivo do dispositivo (NS23; a revogação, NB04) |
| o Duke desligando | `FIM` em cada ponta de fluxo designada, e a operação seguinte ouve `desligando`; nada novo abre nem é aceito (`CONFLICT`) (NS22) |
| escrever num fluxo ainda pedido | `CONFLICT` `o fluxo ainda nao abriu` — espere o `GRAVAVEL` da abertura |
| o canal de eventos cheio | nada: o aviso fica devido, e chega depois — o fim devido, até o teto de 8 designações acabadas do processo ([Limites conhecidos](#limites-conhecidos)) |

## As cotas

| O quê | Quanto |
|---|---|
| canais de eventos na máquina | 190: dois por fio que o escalonador comporta, o pior caso dos processos — estáticos, ~409 KB de RAM fixa |
| canais escutados por processo | 2 (o laço e um de folga) |
| eventos guardados por canal | 64 |
| avisos não consumidos por objeto | 1 |
| designações de objetos que já acabaram, por processo | 8 |
| endpoints por processo / por titular | 4 / 16 |
| fluxos por processo / por titular / na máquina | 4 / 8 / 16 |
| pedidos esperando o aceite, por endpoint | 4 |
| fluxos remotos por relação | 1 |
| o buffer de um sentido, a maior escrita e a maior leitura | 16 KiB |
| o maior pedido e o maior anexo | 4096 bytes e 60 KiB |
| o maior executável | 1 MiB |

Cada operação paga o orçamento dela: as de dados, o do plano de dados; as
de controle, a taxa do papel. O aviso não paga nada, porque não pede nada.

## Construir fora, selar, instalar e rodar

1. **Copie** `sdk/modelo/` para fora do repositório e aponte o
   `programas` e o `protocolo` no `Cargo.toml` — por caminho ou por git, no
   commit cujo `native_interface` é o do Duke em que vai rodar.
2. **Compile** em release, para o alvo do Duke:
   `cargo build --release --target x86_64-unknown-none` (ou
   `aarch64-unknown-none-softfloat`). As opções e o `usuario.ld` do modelo
   são as dos programas da imagem; o `rust-toolchain.toml` dele pede o
   canal do repositório e os dois alvos, que o rustup instala na primeira
   compilação; e o `cargo xtask invariantes` confere que nada divergiu.
3. **Confira**: `cargo xtask sdk-conferir <elf>` diz o nome e as
   permissões do manifesto, o tamanho contra o teto de leitura do kernel,
   o selo, se há, e o resumo BLAKE2s que a auditoria vai citar.
4. **Sele**: `cargo xtask selar <privada do editor> <elf> [--saida
   <arquivo>]`. A ferramenta lê só a chave do editor que recebe — nenhuma
   de dispositivo, de Pessoa ou do Duke —, recusa o ELF sem manifesto
   legível e o já selado, e confere o selo que produziu. O kernel continua
   sem selar nada.
5. **Instale** no armazém pelo gate: `fs.write` com o arquivo no anexo, até
   60 KiB; acima disso, em pedaços de `fs.draft` e um `fs.write` com o
   `draft` — é o que o `instalador` faz.
6. **Rode** com `user.run`, ou pela chamada `executar` de um processo. O
   código de fora da imagem só roda com o selo de um editor que está no
   registro da imagem e em quem o papel de quem lança confia; sem selo,
   adulterado ou de editor estranho, é recusado antes de rodar: o
   `user.run` responde `launched: false` com `CODE_UNSIGNED`,
   `CODE_TAMPERED` ou `CODE_UNTRUSTED`; o `executar` devolve `SEM_SELO`,
   `SELO_NAO_CONFERE` ou `EDITOR_NAO_CONFIADO`, e o processo segue inteiro
   (NS28). Um editor novo é uma imagem nova.

O `cargo xtask sdk-fora` faz os passos 1 a 4 com o modelo, numa cópia em
`target/sdk-fora/` — fora de todo workspace do repositório —, e é o job
"SDK fora do repositório" da CI (NX01–NX03). A bancada da suíte publica o
modelo selado, e as variantes que o Duke recusa, como publica o `vindo`; o
NS28 o instala e roda.

## Testes

- **No hospedeiro** (NH01–NH19): a conta pura do aviso
  (`politica::aviso`) — a borda que publica uma vez, a operação que
  rearma, o espaço só para quem o quer, o fim uma vez, o canal cheio, o
  canal sem ouvinte, a codificação e o evento que só tem o tipo, o número e
  os bits, o fim com o aviso não consumido — junto ao evento da fila, ou
  na espera da operação do dono (NH14) —, o fim devido, no teto do
  processo (NH15), o rearme depois das recusas seguidas (NH17) e, até
  ele, só o que é novo avisando (NH18) — o que o dono ouviria (NH19) —;
  o quadro (`protocolo::quadro`); no xtask, o selo e a lista do contrato,
  com a conferência que acusa o parâmetro tirado, e o ELF forjado recusado
  sem pânico (NH16); e a prontidão que o kernel pergunta, da ponta
  (`politica::fluxo`, NH12) e do endpoint (`politica::malha`, NH13).
- **Na suíte**, nas duas arquiteturas: 46 casos `aviso:` (NS01–NS25, o
  NS01b, NS32–NS36, NS38–NS43, NS45, NS46, NS48–NS54) e 9 casos `sdk:`
  (NS26–NS31, NS37, NS44 e NS47). Os NS32–NS49 vieram da validação final —
  os achados do agente adversário, nas cinco rodadas: o fim com o aviso não consumido, junto ao
  da fila ou na espera do dono, e o teto das designações acabadas; a
  recusa do gate que consome o aviso; quem retira ou fecha; o nome do
  canal no registro; a fila na troca de imagem; o nome do laço tomado; a
  recusa do próprio comando, que espaça o aviso em vez de girar, com a
  vaga que avisa o pedido; só o novo avisando antes do rearme, com outra
  pessoa mexendo na malha; o fim logo depois da operação recusada; a
  recepção que relê sem girar, e o descarte das entregas; o sentido
  fechado pelo par, com o fluxo vivo; a vaga no meio da recusa; o fim que
  chega entre a operação recusada e a conta dela, e o que chega logo
  depois da escrita no sentido fechado; a conta atrasada de outro núcleo,
  que não diz o fim que a operação já ouviu; o fim por fora, que vai à
  cadeia antes de acordar quem espera; o `eco-malha` que fecha o fluxo
  largado pelo cliente; e uma cópia inteira entre dois `copiador`, que
  fecham o fluxo dos dois lados. O NS50 e o NS51 vieram depois do DN-3: a
  vaga que avisa o pedido uma vez, com a recusa que responde a esse aviso
  — a vaga já tomada pelo próprio dono — espaçando até o rearme, em vez de
  avisar de novo na hora; e a vaga que chega no meio de uma recusa, com o
  pedido sem aviso pendente — a ordem contrária à do NS43 —, cujo aviso a
  recusa consome e espaça, sem que o evento se perca. Dentro da janela
  antes do rearme, os dois não esperam linha nenhuma do `avisado`: o "uma
  vez" é provado pelo estado da designação, lido com a hora — o aviso
  visto só no rearme, ou depois, é a máquina que demorou, e o caso o diz
  assim —, e o evento que não se perde, pela conta do canal — os
  publicados, logo depois; os entregues iguais aos publicados, no fim —;
  só no fim, com o `avisado` ocioso, a suíte
  confere o log: cada evento dito uma vez, um ou dois — o do rearme pode
  se juntar ao da vaga, ainda na fila. O NS52 e o NS53 vieram da revisão
  adversária da vaga: a vaga que chega com as marcas dos objetos
  transbordadas — um ponto só da suíte as enche sob a trava delas, logo
  antes da marca da vaga, pelo caminho de sempre: 64 objetos que não
  existem, e mais um que não cabe —, que avisa o pedido na hora, uma vez,
  e não só no rearme; e o rearme que passa no meio de uma recusa, com o
  aviso de antes ainda não consumido, sem apagar a marca da vaga — a
  recusa não espaça, e o aviso da vaga sai logo depois dela. O NS54 veio
  da correção seguinte: o mesmo ponto enche as marcas logo antes da
  mudança de um objeto de outra pessoa — uma entrega a um endpoint dela —,
  e o transbordo avalia tudo — o endpoint que a entrega mudou é avisado —
  sem trazer de volta, antes do rearme, o pedido que a recusa espaçou: o
  aviso não diz ao dono que outro mexeu na malha, e o pedido avisa no
  rearme, uma vez. O programa `avisado` só espera no canal dele e diz
  no log cada aviso que chega; a suíte dita os passos a ele — o caminho
  inteiro pelo runtime — ou pede **como** ele, pela mesma função do gate,
  nos passos que precisam ser exatos. O que se confere é o
  que o kernel publicou, quando e quantas vezes, e que cada operação depois
  de um aviso continua sendo um pedido decidido pelo gate.
- **Os canais**, nas duas arquiteturas: 2 casos `eventos:` novos, da tabela no
  pior caso dos processos (o primeiro dos [Limites
  conhecidos](#limites-conhecidos)). `eventos: o pior caso dos processos
  cabe na tabela`: quatro `avisado`s com dois canais cada, pela chamada; e
  o resto das vagas do escalonador com fios do kernel, até `criar` recusar
  por falta de vaga, cada um pedindo três canais pelo mesmo `escutar` da
  chamada — dois passam, o terceiro ouve o teto, nenhum ouve `OCUPADO` por
  falta de vaga na tabela de canais —; com a tabela de fios cheia, um laço
  a mais ainda sobe, e a varredura dele pergunta uma vez só ao
  escalonador. São fios do kernel, e não processos, que enchem a tabela
  de fios: a suíte não lança noventa programas — a cota de cada titular e
  o custo no ARM —, e o que se prova é a conta: todo fio vivo, com o teto
  dele, cabe. `eventos: o terceiro canal do processo e recusado`: com o
  laço e o segundo abertos, o terceiro canal do `avisado` é recusado com
  `OCUPADO`, com vaga na tabela e o nome livre, e passa com o segundo
  fechado — antes, nenhum caso via o teto por processo.
- **As invariantes de fonte** (NI01–NI03): só `kernel::aviso` publica
  `MALHA`, montado pela conta de `politica::aviso` (NI01), sem nada do
  conteúdo (NI02); e o contrato contra o protocolo, o registro dos
  comandos e a política, nas duas direções, dentro do contrato (NI03).
- **O SDK fora do repositório** (NX01–NX03): o modelo copiado para fora de
  todo workspace, compilado contra o `programas`, conferido e selado, nas
  duas arquiteturas, com os lints da cópia de fora.
- **A bancada** `cargo xtask sdk` (NB01–NB06), nos quatro pares: o modelo
  nas duas máquinas; o `eco-malha` com um cliente de cada máquina e o
  segundo cliente remoto recusado pelo teto da relação; os dois sentidos ao
  mesmo tempo; as medidas e a vazão do laço contra o estilo bloqueante; a
  `conversa` com a pessoa digitando nas duas — cada linha conferida no
  campo dela, na árvore semântica, antes do Enter, como as outras linhas
  das bancadas de duas máquinas (ver [A pessoa no teclado das
  bancadas](ENLACE.md#a-pessoa-no-teclado-das-bancadas)); a revogação no
  meio de um fluxo.

## Mutações

Trinta e duas mutações — N01 a N32 —, uma de cada vez, no repositório, no
x86_64. As da conta pura (`politica::aviso`) rodam os testes do
hospedeiro e os casos da suíte que as veem; as do xtask e do quadro, só os
testes do hospedeiro; as do kernel, do runtime e do protocolo, a suíte
filtrada aos casos `aviso:` e `sdk:` escolhidos para cada uma — de um a
quatro. Na primeira rodada de cada uma sobreviveram cinco — a N03, a N08,
a N11, a N16 e a N28 —, nenhuma por defeito do código: quatro por fraqueza
dos testes, e a N08 porque a campanha não a rodava contra o caso que a
vê:

- **N03** — o caso nomeava, no aceite recusado, o endpoint que a oferta já
  tinha designado: a designação a mais caía sobre a que existia, e a conta
  não mudava. O NS10 ganhou o aceite recusado num endpoint oferecido sem
  `notify`, para outra intenção, que tem de continuar sem designação.
- **N08** — a campanha a rodou contra o NS01 e o NS20, que não a veem: no
  NS01 a leitura esvazia o fluxo, e no NS20 cada leitura também. Quem a vê
  é o NS01b, em que três leituras deixam dado no fluxo e cada uma tem de
  avisar de novo — o despertar perdido de um programa que lê menos que o
  que há.
- **N11** — a janela entre o fecho do dono e o largar da designação não
  aparecia em caso nenhum. Um ponto só da suíte (`modo-teste`) faz a conta
  da ponta nessa janela, como uma operação do par ou o coletor a fariam; o
  NS16 fecha com ele armado, e nada é publicado para quem fechou.
- **N16** — o NS15 só lia depois de a escrita recusada ter acabado o
  fluxo, e a leitura ouvia o motivo, com o gate ou sem ele. A leitura de
  quem recebeu o aviso passou a ser a primeira operação depois da política
  nova — e a mutação ainda passou: dentro da operação, o fluxo reconfirma
  a decisão com a ordem das gravações na mão (DN-2), e a reconfirmação
  recusa a leitura mesmo com a primeira decisão pulada; nenhum byte sai. O
  que a mutação muda é quem recusa — o gate gravaria a leitura como
  permitida —, e o NS15 confere agora que a decisão gravada é a recusa do
  gate.
- **N28** — nenhum caso reusava a vaga de um canal fechado: a designação
  cujo canal sumiu achava a vaga vazia, com ou sem a geração na chave. O
  NS18 põe canais da suíte até um cair na vaga do canal que o processo
  fechou, e o aviso não cruza para ele.

Na última rodada de cada uma, as trinta e duas são reprovadas.

**As da validação final.** Mais trinta e sete — N33 a N69 — conferem as
correções da validação final — os achados do agente adversário, nas cinco
rodadas, e o que os casos novos acharam —, cada uma contra o caso que a
vê. Duas notas. A N45 é a primeira forma da correção do A1 — largar a
designação na hora —, que o NS03 pegou como regressão antes de ela virar
mutação. A N47 (o rearme sem o recuo) foi reprovada pelo teste do
hospedeiro, mas passou no NS38, que aceitava cinco tentativas na janela:
com a mutação, as recusas 3 a 6 rearmam em um segundo e a sétima já cai
no teto de um minuto — cinco. O caso passou a aceitar no máximo três (com
o recuo, são duas), e a N47 é reprovada por ele também.

**A rodada final.** A terceira, a quarta e a quinta rodadas mexeram no
rearme, na vaga, na recepção, na conta e no fim do fluxo, e as sessenta e
nove rodaram de novo, uma de cada vez, contra o código final — dezesseis
delas (N04, N05, N06, N08, N12, N20, N27, N31, N32, N36, N48, N49, N50,
N52, N54 e N59) com o trecho reescrito, porque o código em volta mudou,
para o mesmo efeito. A tabela é o resultado dessa rodada: as sessenta e
nove reprovadas, nenhuma sobrevivente. Depois, a CI 413 achou o NS38
medindo mal — o kernel tinha feito o certo —: o `avisado` diz cada aviso
no log depois de tirá-lo do canal, a primeira espera do caso casava com a
linha atrasada do aviso de um fluxo do preparo, e a linha do aviso
publicado antes das recusas passava pelo de depois delas. O NS38, o NS39
e o NS43 passaram a esperar o `avisado` ocioso — o canal vazio e ele
parado nele — antes da marca, e as onze mutações que eles reprovam (N46 a
N53, N55, N61 e N62) rodaram de novo contra eles: as onze reprovadas.

**Depois do DN-3.** A N70 devolve a vaga que avisava duas vezes: a marca
da vaga que não sai com o aviso publicado — a recusa que responde ao
aviso da vaga não espaça, e o pedido avisa de novo na hora —, contra o
NS50 e o NS51: reprovada pelos dois.

E o fim que a própria sessão com o par conclui — o fim
mandado ao par com o outro sentido já acabado, também o de quem fechou
com tudo dito, que acaba `fechado pela ponta` — ia à cadeia antes de
acordar quem espera, mas fora da ordem das gravações (um achado da
validação de segurança do DN-3): uma operação do dono que
entrasse na ordem nesse meio podia vir antes do fim na cadeia. O envio da
sessão passou a decidir esse quadro com a ordem na mão, a gravar o fim
ali mesmo, como os fins por fora, e só então, com a ordem solta, acordar
quem espera e mandar o quadro. O caso `fluxo: o fim que a sessao com o
par conclui vai a cadeia na ordem` (FS27, em [`FLUXOS.md`](FLUXOS.md))
confere o fim, chegando e saindo — saindo, o de quem fecha com tudo dito,
que conclui o fluxo `fechado pela ponta`, com o `fechar` atrás —, com a
ordem na mão da suíte;
e as N73 a N76 o põem à prova: a conclusão e o fim de novo fora da ordem,
o fim gravado depois de acordar, o fim gravado com a ordem já solta, e o
envio que conclui sem pedir a ordem: as quatro reprovadas por ele. O NS49
passou a conferir também que o fim por fora é gravado com a ordem na mão:
a N77, que o grava com a ordem já solta mas antes de acordar — e que o
NS49 de antes deixava passar —, reprovada por ele.

A revisão adversária dessas duas correções não achou bypass nem registro
perdido; achou dois defeitos baixos que vinham de antes, uma ordem que
também vinha de antes, e duas lacunas dos casos. A vaga se perdia quando
as marcas transbordavam, e o rearme do coletor apagava a marca dela sem
publicar o aviso: as duas correções cabem no que existe — a vaga não se
perde no transbordo das marcas, e o rearme só tira a marca quando o aviso
sai —, e o NS52 e o NS53 as provam; a N78 e a N79 as desfazem. E o fecho
de um fluxo acabado por fora podia sair ao par antes do `stream.end` de
quem o acabou: a sessão passou a decidi-lo também com a ordem na mão, e o
FS28 o prova — a N81 o decide sem ela. As lacunas: o FS27 não via o
quadro mandado com a ordem na mão — o canal de cada lado, na suíte,
passou a conferir a hora de cada quadro, e a N80 manda os quadros da
sessão com a ordem —; e o NS50 e o NS51 esperavam a linha do `avisado`
dentro da janela antes do rearme, e num runner lento podiam dar vermelho
sem defeito: deixaram de esperá-la ali. As quatro foram reprovadas: a
N78 (na primeira forma, abaixo) pelo NS52, a N79 pelo NS53, a N80 pelo
FS27 e pelo FS28, a N81 pelo FS28. A N70 continua vista pelo estado lido
logo depois da recusa que responde ao aviso da vaga, ou que o consome no
meio, e, rodada de novo contra eles, foi reprovada pelos dois; as N73 a
N77, rodadas de novo sobre o código corrigido, continuam reprovadas. A
N71 e a N72 não foram usadas.

A primeira forma da correção da vaga no transbordo — a passada que acha
as marcas transbordadas contava cada endpoint, de qualquer processo,
como talvez com uma vaga — criava um sinal entre pessoas: as marcas são
da máquina inteira, as mudanças de qualquer processo as transbordam, e o
pedido que a recusa de outro processo espaçou avisava antes do rearme —
o dono ficava sabendo que houve muitas mudanças na malha entre duas
passadas. Não concedia nada nem levava conteúdo (o DS-1 continuava de
pé), mas desmentia a regra: o aviso não diz a ninguém quando outro mexeu
na malha. A marca da vaga passou a ficar à parte das dos objetos, fora
do teto delas, uma por processo — e não se perde mais —, e o transbordo
voltou a não contar ninguém como talvez com uma vaga. O NS52 passou a
transbordar as marcas de verdade, pelo caminho de sempre, logo antes da
vaga; o NS54 transborda-as na entrega de outra pessoa e confere que o
pedido espaçado só avisa no rearme. A N78 foi redefinida — a marca da
vaga sujeita ao teto das marcas dos objetos, perdida no transbordo —, e
a N84 devolve a primeira forma: as duas reprovadas, e as N70 e N79,
rodadas de novo sobre o código novo, continuam reprovadas.

E a tabela de canais (o primeiro dos [Limites
conhecidos](#limites-conhecidos)): a conta de dois canais por vaga de
trabalho do escalonador não valia — as vagas de trabalho são o mínimo
garantido, e com menos núcleos os processos passam delas —, e a tabela
passou a ter dois canais por fio que o escalonador comporta, 190,
estáticos; o teto por processo foi para dentro da mesma seção crítica que
insere, e a varredura de cada `escutar` passou a conferir os ouvintes
contra uma fotografia dos fios vivos — uma tomada da tranca do
escalonador por varredura, e não uma por canal. A N82 devolve a tabela a
32, a N83 a põe em dois canais por vaga de trabalho (64), a N86 tira o
teto por processo e a N87 troca a fotografia pela pergunta por canal: as
quatro reprovadas.

Fora do SDK, na mesma numeração: a N85 é a mutação antiga da fase do
NSF — a leitura da auditoria que não avança —, rodada de novo contra o
`nsf: le junto com quem pede` reescrito para esperar pelo andamento dos
fios, e não por prazos de tiques: reprovada. E uma análise de segurança
do Terminal achou que o `set_value` de um agente no campo da janela dele
escapava da regra da linha da pessoa — o Terminal o digitava no
pseudo-terminal, e o texto entrava na linha do nome ou da senha, com o
campo arrendado ao agente e as teclas da pessoa `CONFLICT`. A regra
passou a valer quando a ação entra no kernel, a mesma do console físico,
e o `cancel` pela árvore também deixou de esvaziar essas linhas (ver
[Consoles](../README.md#consoles)). A N88 tira a conferência do campo do
Terminal, e a N89 devolve ao `cancel` da árvore o esvaziar da linha da
senha do físico: as duas reprovadas.

A revisão da documentação pediu que se rodassem de novo as duas mutações
do B4 que tiravam a conta de dentro nas linhas da troca da senha: a última
rodada delas era anterior a esta regra, e, com duas camadas no físico,
tirar uma só podia sobreviver. A N90 (o agente que confirma a troca) e a
N91 (o texto que se escreve nela) continuam reprovadas — o caso da troca
chama a conta de dentro direto. E duas estreitam a regra de fora: a N92,
só no nome e na senha do login, reprovada pelo `pareamento: so pelo
teclado`; a N93, sem as linhas da troca — num Terminal, o `set_value` do
agente chegaria à senha atual ou à nova —, **sobreviveu**: nenhum caso
pedia pela árvore nessas linhas. O caso da troca passou a conferir a regra
de fora no físico, e o do Terminal, a pedir a troca pela janela e
conferir as três recusas na senha atual: a N93, rodada de novo, foi
reprovada pelos dois. E o adversário ξ achou que o valor do `set_value`
no campo do Terminal ia cru ao programa, com o `\n` e o Enter de qualquer
sessão dentro — um agente executava a linha como a serial, o `sistema`,
ou como a pessoa. O campo passou a ter a regra do físico para o que se
digita, e o Enter de um agente só vale quando o kernel entregou o
`confirm` daquela sessão (ver [Consoles](../README.md#consoles)). A N94
tira a regra, a N96 deixa o Enter valer sem pedido, a N97 tira o pedido
do `confirm` legítimo: as três reprovadas. A N95 tira o filtro do
programa do Terminal e sobrevive — o kernel recusa antes; o filtro é
defesa em profundidade. Depois, o adversário ο achou que o pedido do Enter
guardava só o número da sessão — a vaga do transporte, que outra conexão
ocupa quando a do agente acaba, inclusive com um aperto do TCP repetido e
sem confirmação. O pedido passou a ser amarrado à conexão e à chave, como
o dono de uma conexão de rede; o gate deixou de ver a sessão sem
confirmação como do agente; o comando de console que um agente confirmou
e que esperou só é executado de novo na mesma conexão; e o `confirm` de um
agente é recusado com o console esperando ou com os pedidos cheios. A N96
e a N97, redefinidas sobre o código novo, e as N98–N105, reprovadas, as
dez; a N94 e a N95, rodadas de novo: a N94 reprovada, a N95 sobrevivendo
pelo mesmo motivo.

E as do passo 1 da continuidade, a senha fora da auditoria, do log e do
histórico (ver [Consoles](../README.md#consoles)): a linha que não é
comando num console sem ninguém, gravada com um marcador e sem resumo
(N126–N128); o servidor de janelas sem a linha da tecla no log
(N129–N130); a tecla do console físico no histórico quando o console a
consome (N131–N133); o resto da senha engolido até o Enter quando a
cerimônia de pareamento acaba no meio dela (N134–N138); as cópias da
tecla zeradas (N139–N143); quem fechou o Terminal no registro do `logout`
(N144–N147); e o `display.info` sem a conta do que se digita (N148). As
vinte com caso, reprovadas no x86; a N141, a N142 e a N143 ficam sem
caso: a suíte não observa a pilha de outro fio nem a memória de um
processo. E as dos ajustes do passo 1, depois do adversário e do revisor
(N149–N156): o resto da senha engolido também quando o fim da cerimônia
corre com a tecla e com o Enter, e na janela do Terminal; e o desfazer
da anotação de quem fechou, que compara antes de restaurar. Reprovadas no
x86; a N150 e a N155, depois do reforço dos casos. E as do achado F1 do
adversário do AE-1 — o motivo que o corte do detalhe tirava, e o NSF que
deixava de ver o código adulterado — e do #292, o erro da leitura sem heap
no `executar` (N157–N161): o corte antigo, que encolhia o texto antes da
descrição do programa (N157); o reconhecimento da falta só pelo motivo
inteiro (N158); a leitura sem heap dizendo `PROGRAMA_DESCONHECIDO` (N159);
o grafo do NSF tomando a descrição abreviada por outro programa do
processo (N160); e o editor que sai da descrição sem deixar o `de ?` — o
código de fora da imagem passando pelo da imagem (N161). Todas reprovadas:
a N157, a N160 e a N161 pelos testes do hospedeiro e pela suíte do x86; a
N159, que é do kernel, pela suíte; e a N158 só pelos do hospedeiro — com a
descrição encolhendo antes, a suíte não produz um motivo de procedência
cortado. E as do passo 1 da continuidade que fecham a corrida do L1 — a
edição da árvore que corre com o Enter da Pessoa, conferida de novo
quando o console a consome — e o #297 — o aviso atrasado do fim da
cerimônia, que mudava a linha do login (N162–N172; ver
[Consoles](../README.md#consoles)): a conferência do consumo tirada, e a
corrida volta (N162); o arrendamento solto sem conferir de quem é (N163);
o arrendamento da recusada não solto (N164); o que vem marcado sem
reserva passando como a tecla da Pessoa (N165); o aviso que mexe de novo
em qualquer linha (N166); a sequência de recusadas sem conferir que cada
edição começa onde a anterior deixou o campo (N167); a recusa que não
fica com a edição inteira (N168); o bit do histórico pelo modo da
cerimônia, e não pelo da linha que ficou (N169); o arrendamento que a
edição só renovou, solto (N170); a sequência que não conta — só a
edição que tomou o arrendamento o solta (N171); e o aviso que mexe de novo
nas linhas da troca da senha, e só nelas (N172). Todas reprovadas no x86,
uma de cada vez. E as do resíduo do F1, depois do adversário dele — os
registros sem citação que o anel cortava, o corte no meio de um nome e as
regressões do NSF (N173–N181; ver *O NSF vê o adulterado*, no
[README](../README.md#o-código-de-fora-da-imagem)): a saída antecipada de
volta, e o registro sem citação não encolhe (N173); o nascimento que
sobrescreve o processo que já nasceu (N174); o `filho N` até o fio do pai
aceito como nascimento (N175); o texto cortado no meio da palavra (N176);
a falta reconhecida sem tirar a marca do corte (N177); o grafo que ignora
a abreviada de outro resumo (N178); a regra do firewall casada também
pelo programa (N179); o corte sem a marca (N180); e o editor
`desconhecido` aceito no registro (N181). Todas reprovadas pelos testes
do hospedeiro, uma de cada vez; a N173, a N176 e a N180 também pela suíte
do x86 — as outras mexem no que a suíte não produz: um registro cortado
ou repetido, um motivo de procedência cortado, uma troca abreviada, uma
execução barrada de descrição longa, um editor com o nome reservado. E a
N160 de novo, na forma do código novo — o grafo toma a abreviada por
outro programa —: reprovada pelos testes do hospedeiro e pela suíte do
x86. E a do retrato do `system.info time` (a CI 432; ver *O retrato do
`system.info time`*, em [A rodada](../README.md#a-rodada)): o
civil lido antes de esperar a vez da hora, como era (N182) — reprovada
pela suíte do x86. E as do AE-5 e dos achados do adversário do passo 1
(N183–N197): a reserva do nome `desconhecido` de volta no registro de
chaves de atualização (N183, o achado 4); o recolhimento que não limpa os
zumbis (N184) e a colheita que limpa de novo a morte que o zumbi já soltou
(N185), o item 1; o fio da energia sem o gancho da suíte (N186, o item 2);
a execução da decisão que recalcula quem pede (N187, o F2); a volta "no
meio" sem a execução adiada (N188, o F5, num núcleo só); a entrega sem a
conferência antes da conta (N189) e a edição que só renovou e não chegou
sem passar a renovação adiante (N190), o achado 1; a linha que passa a
pedir a pessoa sem recusar as edições a caminho (N191, o achado 2); a
soltura gravada de novo como `ui.release` (N192, o achado 5); o consumo
sem conferir de novo quem pediu a edição (N193, o achado 7); a
conferência do `xtask` só pela chamada com o caminho (N194, o achado 8); o
`definir` do físico sem a regra da linha da pessoa na seção que edita
(N195, o item 4); o grafo do NSF comparando a abreviada só pelo resumo
(N196, o achado 3); e o aviso de qualquer cerimônia mudando a linha (N197,
o achado 6). Todas reprovadas, uma de cada vez: a N183, a N194 e a N196
pelos testes do hospedeiro; as outras pela suíte do x86, filtrada aos
casos de cada uma — a N188 num núcleo só (`DUKE_NUCLEOS=1`). E as dos
achados do adversário do passo 1b (N198–N204): o consumo da edição da
árvore sem perguntar à contenção (N198) e a soltura de quem foi contido
com o motivo de quem saiu da sessão (N204), o achado 2; o Enter que escreve
na linha o passo que leu, mesmo de antes do que ela mostra (N199), o que
põe de volta na linha a cerimônia que acabou depois da leitura (N200), e
o aviso atrasado que volta a linha a um passo de antes (N201), o achado
3; e o `xtask` que deixa passar o `#[path]` fora da suíte (N202) e a
conta que devolve o rastro fora dos nomes protegidos (N203), o achado 6.
Todas reprovadas, uma de cada vez: a N202 e a N203 pelos testes do
hospedeiro; as outras pela suíte do x86, filtrada aos casos de cada uma
— a N204 depois do reforço do caso da contenção, que passou a conferir a
conta que corre com ela. E as dos achados do adversário do passo 1c
(N205–N208): o consumo que aceita a sessão da pessoa que acabou (N205) e
a reserva de pessoa sem a sessão dela (N206), o achado 1; o `xtask` que só
vê o `path` logo depois do `#[` (N207), o achado 2; e o aviso da
cerimônia que escreve o bit do histórico de novo depois de soltar a trava
(N208), o achado 3. Todas reprovadas, uma de cada vez: a N207 pelos
testes do hospedeiro; as outras pela suíte do x86, filtrada aos casos de
cada uma. E as da CI 437 — a conta dos casos da ordem presa, que passou a
aceitar as voltas que o coletor adia depois da soltura, cada uma dita —:
a troca que chega ao fim gravando também uma execução da decisão (N209),
e de novo a N111, a volta adiada sem a execução, contra a conta nova. As
duas reprovadas pela suíte do x86, filtrada aos casos da troca. E as do
diagnóstico do firmware parado (#310, N210–N220; ver *O firmware parado da
CI 436* em [`PERSISTENCIA.md`](PERSISTENCIA.md#o-firmware-parado-da-ci-436)):
o cabeçalho comparado com o `ImageBase` da memória (N210), a imagem de
baixo sem conferir que vai até o endereço (N211), o caminho do CodeView
lido do lugar errado (N212, N213), os valores vizinhos da pilha repetidos
(N214), o `\r` dos registradores (N215), a seção GUID lida sem o
`DataOffset` (N216), a procura da pilha que marca vazia só uma página
(N217), o ponteiro para os dados de uma imagem tomado por retorno (N218),
a pilha no fim da memória que não se lê nada (N219) e o arquivo de
enchimento do volume tomado pelo espaço livre (N220).
Todas reprovadas, uma de cada vez, pelos testes do hospedeiro do `xtask`;
a N212 sobreviveu à primeira rodada — o caminho lido quatro bytes antes
ainda acabava no mesmo nome — e foi reprovada depois do reforço do teste.
E as da ordem de boot da máquina (#313, N221–N228; ver *A ordem de boot*
em [`PERSISTENCIA.md`](PERSISTENCIA.md#a-ordem-de-boot)): o IDE do boot
sem `bootindex` (N221), o `disco0` do NVMe e do ARM sem ele (N222), o x86
com o disco no virtio bootando pelo `disco0` (N223), a máquina sem
firmware com ordem (N224), e a conferência da linha do emulador que aceita
duas ordens (N225), a ordem noutro dispositivo (N226), a ordem numa
máquina sem firmware (N227) e outro valor (N228). Todas reprovadas, uma
de cada vez, na primeira rodada, pelos testes do hospedeiro do `xtask`.
E a do fim do disco hostil (#314, N229; ver *O disco hostil* em
[`PERSISTENCIA.md`](PERSISTENCIA.md#o-disco-hostil)): o `Drop` sem esperar
o fio do servidor — reprovada pelo teste do hospedeiro do `xtask`, com o
servidor segurando a descarga antes de aplicá-la. E as
do motivo da recusa (CI 439, N230 e N231; ver *O disco hostil* em
[`PERSISTENCIA.md`](PERSISTENCIA.md#o-disco-hostil)): toda recusa marcando
a máquina, e o motivo lido com o leitor de campo simples — reprovadas, uma
de cada vez, pelo teste do hospedeiro do `xtask`.

| | Mutação | Reprovada por |
|---|---|---|
| N01 | a designação sem conferir que o processo escuta o canal | NS08 |
| N02 | o descritor que não é canal, ignorado em silêncio | NS09 |
| N03 | a recusa do gate que ainda designa o endpoint do pedido | NS10, depois do reforço |
| N04 | o primeiro byte do fluxo no campo `b` do aviso | NS12 |
| N05 | o aviso da ponta no canal do par | NS13 |
| N06 | sem coalescência: toda mudança publica | NH01, NH05, NH14; NS01 |
| N07 | sem rearme depois da operação do dono | NH02, NH03, NH14; NS01, NS26 |
| N08 | o rearme sem reavaliar a prontidão | NS01b |
| N09 | o `GRAVAVEL` nunca publicado | NH03, NH06, NH14, NH19; NS02, NS06 |
| N10 | o `FIM` não publicado no aborto | NS03, NS22, NS23 |
| N11 | o aviso depois da lápide vista | NS16, depois do reforço |
| N12 | o `exec` mantendo as designações | NS17 |
| N13 | o canal sem ouvinte tentado para sempre | NS18 |
| N14 | o canal cheio descartando o aviso | NS19 |
| N15 | o devido entregue duas vezes | NS19 |
| N16 | a leitura depois do aviso sem o gate | NS15, depois do reforço |
| N17 | o `notify` de um agente ou de uma pessoa aceito | NS14 |
| N18 | sem `ENTREGA` no endpoint | NS04 |
| N19 | sem `PEDIDO` no endpoint | NS04 |
| N20 | o despertar da sessão remota sem o aviso | NS24 |
| N21 | a ponta aceita de outro Duke, sem aviso | NS25 |
| N22 | `native_interface` sem subir | NS30 |
| N23 | a conferência do contrato aceitando um parâmetro tirado | o teste do hospedeiro do xtask |
| N24 | selar sem conferir o manifesto | NH10 |
| N25 | o laço parando no tipo de evento que não conhece | NS05 |
| N26 | o quadro aceitando a mensagem maior que o teto | NH09 |
| N27 | um bit de coalescência partilhado entre os objetos do canal | NS20 |
| N28 | a chave do canal sem a geração | NS18, depois do reforço |
| N29 | o pedido que abre, aceito no desligamento | NS22 |
| N30 | a designação passando ao filho no `fork` | NS08 |
| N31 | o aviso seguinte do mesmo objeto noutro lugar da fila | NS01b |
| N32 | a latência do aviso sem medida | NS31 |
| N33 | o fim com o aviso não consumido que não fica na espera | NH14; NS32 |
| N34 | as designações acabadas sem o teto do processo | NS32 |
| N35 | a recusa do gate que não consome o aviso | NS33 |
| N36 | só a recepção que passou consome o aviso | NS33 |
| N37 | a retirada que larga a designação depois de acordar (o `FIM` a quem retirou) | NS34 |
| N38 | o fecho recusado que larga a designação do fluxo vivo | NS34 |
| N39 | o nome do canal cru no registro da designação | NS35 |
| N40 | a troca de imagem que deixa os avisos na fila | NS36 |
| N41 | a leitura do ELF sem o tamanho do cabeçalho de programa | NH16 |
| N42 | a leitura do ELF com a conta que transborda | NH16 |
| N43 | o laço que não tenta outro nome | NS37 |
| N44 | o fim que não se junta ao aviso que espera na fila | NS32 |
| N45 | o fim com o aviso não consumido largado na hora (o `FIM` perdido) | NH01, NH14; NS03, NS32 |
| N46 | o aceite recusado pelo comando que rearma na hora (o giro) | NS38 |
| N47 | o rearme sem o recuo | NH17; NS38, depois do reforço |
| N48 | o fim do fluxo que não dá a vaga aos processos dele | NS38 |
| N49 | a recusa seguida que empurra o rearme marcado | NS38 |
| N50 | sem o filtro do que é novo: a mudança alheia traz o aviso recusado antes do rearme | NS38, NS39 |
| N51 | a vaga que não esquece o nível recusado | NS38 |
| N52 | o filtro que segura também o novo | NS39 |
| N53 | o novo contado ao contrário na conta pura | NH18, NH19; NS39 |
| N54 | o objeto acabado que espera o rearme da recusa | NS40 |
| N55 | a vaga que chega no meio da recusa, ignorada | NS43 |
| N56 | a recepção que relê o que já leu, contada como a que passou (o giro do `ENTREGA`) | NS41 |
| N57 | o aceite sem pedido que desfaz o espaçamento | NS41 |
| N58 | o descarte que lê e não confirma | NS41 |
| N59 | o fim só do sentido que larga a designação do fluxo vivo | NS42 |
| N60 | o `eco-malha` que larga o cliente sem fechar o fluxo | NS44 |
| N61 | a vaga dada ao dono do endpoint pelo pedido que acaba sem aceite | NS39 |
| N62 | a vaga dada aos endpoints de qualquer processo | NS39 |
| N63 | a recusa espaçada que não refaz a conta depois da trava (o fim no meio dela, perdido) | NS45 |
| N64 | o `Encerrado` que larga a designação quando o fluxo acabou depois da operação | NS46 |
| N65 | o `copiador` que manda e não fecha o fluxo | NS47 |
| N66 | o `copiador` que não reconhece o diretório que já existe (só a primeira cópia de cada Duke) | NS47 |
| N67 | a conta que publica o nível perguntado antes da operação do dono (o `FIM` que ela já ouviu) | NS48 |
| N68 | o filtro do que é novo pelo nível cru, e não pelo que o dono ouviria | NH19 |
| N69 | o fim por fora gravado depois de acordar quem espera | NS49 |
| N70 | a marca da vaga que não sai com o aviso publicado (o segundo aviso da mesma vaga: a recusa que responde ao aviso dela, ou a que o consome no meio, não espaça) | NS50, NS51 |
| N73 | o fim que a sessão com o par conclui, de novo fora da ordem das gravações | FS27 |
| N74 | o fim que a sessão com o par conclui, gravado depois de acordar quem espera | FS27 |
| N75 | o fim que a sessão com o par conclui, gravado com a ordem já solta | FS27 |
| N76 | o envio da sessão que conclui o fluxo sem pedir a ordem | FS27 |
| N77 | o fim por fora gravado com a ordem já solta, antes de acordar | NS49 |
| N78 | a marca da vaga sujeita ao teto das marcas dos objetos, perdida no transbordo: o pedido só avisa no rearme (redefinida) | NS52 |
| N79 | o rearme do coletor que apaga a marca da vaga sem publicar o aviso dela | NS53 |
| N80 | o quadro da sessão com o par mandado com a ordem das gravações na mão | FS27, FS28 |
| N81 | o fecho de um fluxo acabado decidido sem a ordem das gravações | FS28 |
| N82 | a tabela de canais de volta a 32 | `eventos: o pior caso dos processos cabe na tabela` |
| N83 | a tabela de canais com dois por vaga de trabalho, 64 | `eventos: o pior caso dos processos cabe na tabela` |
| N84 | o transbordo que conta todo endpoint como talvez com uma vaga — a primeira forma da correção, o sinal entre pessoas | NS54 |
| N85 | fora do SDK: a leitura da auditoria do NSF que não avança — a mutação antiga da fase do NSF, contra o caso reescrito para esperar pelo andamento | `nsf: le junto com quem pede` |
| N86 | o `escutar` sem o teto por processo | `eventos: o terceiro canal do processo e recusado`, `eventos: o pior caso dos processos cabe na tabela` |
| N87 | a varredura que pergunta ao escalonador por canal, e não pela fotografia dos fios vivos | `eventos: o pior caso dos processos cabe na tabela` |
| N88 | o campo da janela do Terminal sem a regra da linha da pessoa: o `set_value`, o `cancel` e o `confirm` de um agente chegam à linha do nome ou da senha | `terminal: o agente nao edita nem confirma a linha da senha` |
| N89 | o `cancel` da árvore que esvazia a linha da senha do console físico | `consoles: login e logout` |
| N90 | fora do SDK: o agente que confirma as linhas da troca da senha na conta do console (a M33 do B4, de novo depois da regra) | `senha: a pessoa troca a propria, e a antiga nao entra mais` |
| N91 | fora do SDK: o texto que se escreve nas linhas da troca da senha na conta do console (a M34 do B4, com o texto de hoje) | `senha: a pessoa troca a propria, e a antiga nao entra mais` |
| N92 | fora do SDK: a regra de fora da linha da pessoa só no nome e na senha do login | `pareamento: so pelo teclado` |
| N93 | fora do SDK: a regra de fora da linha da pessoa sem as linhas da troca da senha | `senha: a pessoa troca a propria, e a antiga nao entra mais`, `terminal: o agente nao edita nem confirma a linha da senha` — depois do reforço |
| N94 | fora do SDK: o campo do Terminal sem a regra do que se digita — o `set_value` com o `\n` ou o Enter de uma sessão passa | `terminal: o agente nao edita nem confirma a linha da senha` |
| N95 | fora do SDK: o Terminal que digita do pedido da árvore qualquer caractere | **sobreviveu**: o kernel recusa o valor antes; o filtro do programa é defesa em profundidade |
| N96 | fora do SDK: o Enter de um agente que vale sem pedido — o número dentro do caractere de novo como autoridade | `terminal: o Enter de agente que a arvore nao pediu e descartado` |
| N97 | fora do SDK: o `confirm` de um agente no Terminal que não pede o Enter dele | `terminal: o agente nao edita nem confirma a linha da senha` |
| N98 | fora do SDK: o Enter pedido amarrado só ao número da sessão — vale para quem estiver na vaga | `terminal: o Enter pedido e so da conexao que o pediu` |
| N99 | fora do SDK: o gate que vê o aperto do TCP sem confirmação como do agente cuja chave ele alega | `terminal: o Enter pedido e so da conexao que o pediu` |
| N100 | fora do SDK: a amarração que aceita a sessão do TCP sem confirmação | `terminal: o Enter pedido e so da conexao que o pediu` |
| N101 | fora do SDK: o comando suspenso de um agente reexecutado sem a amarração | `terminal: o Enter pedido e so da conexao que o pediu` |
| N102 | fora do SDK: o Enter de agente reservado com o console esperando um comando | `rede: o console espera e segura a entrada` |
| N103 | fora do SDK: os pedidos de Enter cheios que despejam o mais velho | `terminal: o Enter de agente que a arvore nao pediu e descartado` |
| N104 | fora do SDK: o `set_value` sem valor num campo de janela recusado só depois da conta | `terminal: o agente nao edita nem confirma a linha da senha` |
| N105 | fora do SDK: os marcadores do pedido dentro do valor, na linha de comando do toolkit | o teste do toolkit `o_agente_na_linha_de_comando_vira_o_que_digitar` |
| N106 | fora do SDK: a camada que sai da pilha sem recompor o lugar dela — a da corrida do caso das superfícies na CI 419 | `compositor: a camada de cima vence`, `compositor: escrever debaixo nao vaza`, `compositor: camada na borda`, `compositor: transparencia`; o caso das superfícies não a vê: a rolagem do eco do coletor recompõe o console por cima |
| N107 | fora do SDK (AE-1): a troca de imagem de quem é ponta de fluxo sem a conferência sem espera antes do gate — a espera decide e grava a cada volta | `fluxo: a troca de imagem com fluxo e a ordem com outro fio`, `fluxo: a troca de imagem com a ordem tomada no meio`, `fluxo: a troca de imagem adiada abre a janela das interrupcoes`, `fluxo: a troca de imagem adiada da a vez a quem tem a ordem` |
| N108 | fora do SDK (AE-1): a ordem das gravações esperada no ponto sem volta, dentro do handler | `fluxo: a troca de imagem com fluxo e a ordem com outro fio`; `fluxo: a troca de imagem com a ordem tomada no meio` — a asserção da espera mascarada |
| N109 | fora do SDK (AE-1): toda troca de imagem tomando a ordem, também a de quem não é ponta | `fluxo: a troca de imagem sem fluxo nao espera a ordem` |
| N110 | fora do SDK (AE-1): o fim dos fluxos da troca num fio do kernel, depois de a imagem nova rodar | `fluxo: a troca de imagem com fluxo e a ordem com outro fio`, `fluxo: a troca de imagem com a ordem tomada no meio`, `fluxo: a troca de imagem adiada abre a janela das interrupcoes`, `fluxo: a troca de imagem adiada da a vez a quem tem a ordem` |
| N111 | fora do SDK (AE-1): a volta adiada depois de decidida sem a execução da decisão (`CONFLICT`) | `fluxo: a troca de imagem com a ordem tomada no meio` |
| N112 | fora do SDK (AE-1): a troca que falha antes do ponto sem volta sem a execução da decisão (`ERROR`) | `fluxo: a troca de imagem que falha antes do ponto sem volta` |
| N113 | fora do SDK (AE-1): o resto da carga — o espaço anterior largado, os segmentos e a pilha — com a ordem das gravações na mão | os quatro casos da troca de quem é ponta com a ordem com outro fio: `com fluxo e a ordem com outro fio`, `com a ordem tomada no meio`, `adiada abre a janela das interrupcoes`, `adiada da a vez a quem tem a ordem` |
| N114 | fora do SDK (AE-1): a janela das interrupções do x86 vazia | `fluxo: a troca de imagem adiada abre a janela das interrupcoes` — o núcleo da troca adiada conta zero tique em trinta do relógio |
| N115 | fora do SDK (AE-1): a janela do x86 sem o `nop` — `sti; cli` | `fluxo: a troca de imagem adiada abre a janela das interrupcoes` — zero tique em trinta |
| N116 | fora do SDK (AE-1): a ponta de fluxo contada por qualquer fluxo vivo na máquina | `fluxo: a troca de imagem sem fluxo nao espera a ordem` |
| N117 | fora do SDK (AE-1): a ordem tomada sem esperar que compacta o journal | os quatro casos da troca de quem é ponta com a ordem com outro fio |
| N118 | fora do SDK (AE-1): a repetição da troca adiada sem a cessão | `fluxo: a troca de imagem adiada da a vez a quem tem a ordem`, no aarch64 — 3138 trocas adiadas em 20 voltas do outro fio; no x86, **sobrevive** por construção: `estacionar` cede sempre |
| N119 | fora do SDK (AE-1): a ordem solta entre a troca e o fim dos fluxos, sem a asserção da depuração — como na release | os quatro casos da troca de quem é ponta com a ordem com outro fio |
| N120 | fora do SDK (AE-1): a troca que falha antes do ponto sem volta encerrando os fluxos | `fluxo: a troca de imagem que falha antes do ponto sem volta` |
| N121 | fora do SDK (AE-1): a ponta tratada como quem não é | a conferência da premissa, na suíte, depois da troca: o kernel para com `o processo virou ponta de fluxo no meio da troca de imagem sem a ordem` |
| N122 | fora do SDK (AE-1c): o arquivo que não se lê, depois do gate, sem a execução da decisão (`ERROR`) | `fluxo: a troca de imagem cujo arquivo nao se le` |
| N123 | fora do SDK (AE-1c): a imagem nova que não se mapeia, depois do ponto sem volta, sem a execução da decisão (`ERROR`) | `fluxo: a troca de imagem que falha depois do ponto sem volta` |
| N124 | fora do SDK (AE-1c): a falha do mapeamento tratada como a de antes do ponto sem volta — o erro devolvido ao processo, que volta sem imagem | `fluxo: a troca de imagem que falha depois do ponto sem volta` — o processo morre de falha de página na própria instrução, e não sai com `SEM_MEMORIA` |
| N125 | fora do SDK (AE-1c): a falha do mapeamento provocada antes do ponto sem volta — o gancho que não chega lá | `fluxo: a troca de imagem que falha depois do ponto sem volta` — o processo ouve o erro e segue vivo |
| N126 | fora do SDK (passo 1, N6): num console sem ninguém, o nome de qualquer linha gravado como método, como antes | `consoles: nada antes do login` |
| N127 | fora do SDK (passo 1, N6): o marcador da linha que não é comando gravado com o resumo dos parâmetros | `consoles: nada antes do login` — o resumo do marcador não é o do vazio |
| N128 | fora do SDK (passo 1, N6): o comando que existe gravado com o marcador | `consoles: nada antes do login` |
| N129 | fora do SDK (passo 1, N2): o servidor de janelas grava de novo `janelas: tecla <código> em <id>` | `janelas: o servidor abre, foca, arrasta e fecha`, `janelas: a arvore semantica atravessa a fronteira`, `janelas: sobre o duke pela barra`, `janelas: cada superficie recebe a sua entrada` |
| N130 | fora do SDK (passo 1, N2): uma linha por tecla, sem o código — a conta e o ritmo da senha | os mesmos quatro casos `janelas:` |
| N131 | fora do SDK (passo 1): a tecla do console físico no histórico quando chega, e não quando o console a consome | `consoles: a senha digitada adiantado nao entra no historico` |
| N132 | fora do SDK (passo 1): o consumo grava a tecla de função e o clique | `barra: F1 da pessoa pressiona` |
| N133 | fora do SDK (passo 1): o consumo grava sem a guarda de quem pede senha | `consoles: a senha digitada adiantado nao entra no historico`, `consoles: login e logout` |
| N134 | fora do SDK (passo 1, N5): o fim da cerimônia no meio da senha não engole — o resto ecoa e vira comando | `pareamento: o fim no meio da senha engole o resto` |
| N135 | fora do SDK (passo 1, N5): o Enter não acaba o engolir | `pareamento: o fim no meio da senha engole o resto` — o console não volta |
| N136 | fora do SDK (passo 1, N5): a árvore edita e confirma a linha que engole | `pareamento: o fim no meio da senha engole o resto` |
| N137 | fora do SDK (passo 1, N5): o bit da senha desligado enquanto o console engole | `pareamento: o fim no meio da senha no fisico nao vai ao historico` |
| N138 | fora do SDK (passo 1, N5): engolir também com a linha da senha já confirmada — a linha seguinte some | `smp: o fim da cerimonia com a senha ja confirmada nao engole` |
| N139 | fora do SDK (passo 1, X5): `eventos::colher` sem zerar a posição entregue | `eventos: a fila do canal nao guarda o que entregou` |
| N140 | fora do SDK (passo 1, X5): `eventos::descartar` sem zerar as posições que sobram | `eventos: a fila do canal nao guarda o que entregou` |
| N141 | fora do SDK (passo 1, X5): `escrever_no_terminal` sem zerar a cópia na pilha do kernel | **sem caso**: a pilha do kernel de outro fio não é observável pela suíte — a defesa é a revisão da `politica::sigiloso::zerar`, cujo efeito nenhum teste confere (os do hospedeiro conferem o `zerar_bloco`) |
| N142 | fora do SDK (passo 1, X5): `ler_eventos` do kernel sem zerar os bytes de cada evento | **sem caso**, pelo mesmo motivo |
| N143 | fora do SDK (passo 1, X5): o runtime sem zerar a leitura dos eventos — a cópia de cada um e os bytes, na volta com eventos | **sem caso**: a memória do processo não é observável pela suíte |
| N144 | fora do SDK (passo 1): o `press` da árvore na caixa de fechar do Terminal sem a anotação | `terminal: digita e mostra a resposta` — o `logout` do agente sai como o clique |
| N145 | fora do SDK (passo 1): o Terminal sai sem fechar o pseudo-terminal | `terminal: digita e mostra a resposta` — o `press` do agente, o primeiro fechamento do caso, sai como `o terminal morreu` |
| N146 | fora do SDK (passo 1): `pseudoterminal::fechar` sem olhar a anotação | `terminal: o logout diz quem fechou`, `terminal: digita e mostra a resposta` |
| N147 | fora do SDK (passo 1): a anotação que não se desfaz quando o evento não chega ao Terminal | `terminal: digita e mostra a resposta` — a fila do Terminal cheia, com ele preso ao núcleo da suíte |
| N148 | fora do SDK (passo 1, N3): o `display.info` com `terminal.typed` de novo | `agente: display.info descreve a pilha` |
| N149 | fora do SDK (ajustes do passo 1, A1): a letra que passou pelo engolir antes do fim chega à linha sem conferir o engolir | `pareamento: o fim entre duas tomadas da linha nao deixa a senha nem engole a seguinte` |
| N150 | fora do SDK (ajustes do passo 1, A1): o apagar sem conferir o engolir | `pareamento: o fim entre duas tomadas da linha nao deixa a senha nem engole a seguinte` — depois do reforço: o caso põe algo na linha enquanto ela engole, o que nenhum caminho de hoje põe; sem isso sobrevivia, equivalente |
| N151 | fora do SDK (ajustes do passo 1, A1): o Enter que acaba o engolir sem apagar a linha | `pareamento: o fim entre duas tomadas da linha nao deixa a senha nem engole a seguinte` — o caso põe algo na linha enquanto ela engole |
| N152 | fora do SDK (ajustes do passo 1, A2): o Enter que leu a linha da senha antes do fim não acaba o engolir | `pareamento: o fim entre duas tomadas da linha nao deixa a senha nem engole a seguinte` — o console fica engolindo |
| N153 | fora do SDK (ajustes do passo 1, A6): a janela do Terminal põe na coordenação o que o console engole | `pareamento: o terminal de verdade engole fora da coordenacao` |
| N154 | fora do SDK (ajustes do passo 1, A6): a janela não conta o Enter, e as teclas depois dele também ficam fora da coordenação | `pareamento: o terminal de verdade engole fora da coordenacao` |
| N155 | fora do SDK (ajustes do passo 1, A6): a tecla engolida que a janela não entrega cai no console físico | `pareamento: a tecla engolida que o terminal morto nao recebe some` — depois do reforço: com a fila do Terminal cheia, que conta como entregue, sobrevivia |
| N156 | fora do SDK (ajustes do passo 1, I1): o desfazer da anotação de quem fechou restaura às cegas | `terminal: o logout diz quem fechou` |
| N157 | fora do SDK (F1): o corte antigo do detalhe composto — a descrição do programa não encolhe, e o texto perde o fim primeiro | hospedeiro: `auditoria::testes::a_descricao_encolhe_antes_do_motivo`, `a_descricao_abreviada_nao_e_a_de_outro_programa`, `o_motivo_cortado_ainda_diz_a_falta`, `o_detalhe_composto_guarda_a_citacao`; `evento::testes::a_falta_de_quem_tem_descricao_longa`; `o_codigo_adulterado_de_quem_tem_descricao_longa` (o motor); suíte: `nsf: ve o codigo adulterado de quem tem descricao longa`, `fluxo: a troca de imagem cujo arquivo nao se le`, `fluxo: a troca de imagem cujo arquivo nao cabe no heap` |
| N158 | fora do SDK (F1): a falta reconhecida só pelo motivo inteiro, sem o começo essencial | hospedeiro: `procedencia::testes::o_motivo_cortado_ainda_diz_a_falta`, `auditoria::testes::o_motivo_cortado_ainda_diz_a_falta`, `evento::testes::a_falta_de_quem_tem_descricao_longa` — a suíte não corta o motivo de procedência depois do encolhimento da descrição |
| N159 | fora do SDK (#292): a leitura que falhou sem heap no `executar` volta a dizer `PROGRAMA_DESCONHECIDO` | `fluxo: a troca de imagem cujo arquivo nao cabe no heap` |
| N160 | fora do SDK (F1): o grafo do NSF toma a descrição abreviada por outro programa do processo — rodada de novo no resíduo do F1, na forma do código novo | hospedeiro: `grafo::testes::a_descricao_abreviada_nao_troca_o_programa`, `a_abreviada_de_outro_resumo_e_uma_troca`; o motor: `o_codigo_adulterado_de_quem_tem_descricao_longa`, `a_troca_que_morre_no_mapeamento_fica_no_grafo`; suíte x86, filtrada (894 de 895 na conta do harness, que dá os pulados como passados): `nsf: ve o codigo adulterado de quem tem descricao longa` |
| N161 | fora do SDK (F1): o editor sai da descrição sem deixar o `de ?` — o código de fora da imagem passa pelo da imagem | hospedeiro: `auditoria::testes::a_descricao_encolhe_antes_do_motivo`, `a_descricao_abreviada_nao_e_a_de_outro_programa`, `o_motivo_cortado_ainda_diz_a_falta`; `evento::testes::a_falta_de_quem_tem_descricao_longa`; `o_codigo_adulterado_de_quem_tem_descricao_longa` (o motor); suíte: `nsf: ve o codigo adulterado de quem tem descricao longa` |
| N162 | fora do SDK (passo 1, L1): a conferência do consumo tirada — o que vem marcado da árvore entra em qualquer linha, e a corrida volta | `terminal: a edicao da arvore que corre com o Enter da pessoa nao entra na linha do nome`, `terminal: so se solta o arrendamento que as edicoes recusadas deixaram`, `pareamento: a edicao da arvore que corre com o Enter do aceitar nao entra na linha da cerimonia`, `pareamento: a edicao recusada na linha da cerimonia continua recusada quando a linha volta a pedir um comando`, `terminal: a marca da arvore sem reserva nao solta nem passa nada` |
| N163 | fora do SDK (passo 1, L1): o arrendamento solto sem conferir de quem é — sai o de quem estiver no campo | `terminal: so se solta o arrendamento que as edicoes recusadas deixaram` — a primeira de duas edições em voo solta o que a segunda renovou |
| N164 | fora do SDK (passo 1, L1): o arrendamento que a edição recusada tomou não sai | `terminal: a edicao da arvore que corre com o Enter da pessoa nao entra na linha do nome`, `terminal: so se solta o arrendamento que as edicoes recusadas deixaram`, `pareamento: a edicao da arvore que corre com o Enter do aceitar nao entra na linha da cerimonia`, `pareamento: a edicao recusada na linha da cerimonia continua recusada quando a linha volta a pedir um comando` |
| N165 | fora do SDK (passo 1, L1): a marca aceita sem reserva — o que vem marcado sem reserva passa como a tecla da Pessoa | `terminal: a marca da arvore sem reserva nao solta nem passa nada`, `pareamento: a edicao recusada na linha da cerimonia continua recusada quando a linha volta a pedir um comando` — a linha que engole |
| N166 | fora do SDK (passo 1, #297): o aviso da cerimônia mexe de novo em qualquer linha | `pareamento: o aviso atrasado do fim nao muda a linha do nome nem a da senha do login` |
| N167 | fora do SDK (passo 1, L1): a sequência de recusadas sem conferir que cada edição começa onde a anterior deixou o campo | `terminal: so se solta o arrendamento que as edicoes recusadas deixaram` — a edição seguinte ao `ui.claim` |
| N168 | fora do SDK (passo 1, L1): a recusa que não fica com a edição inteira — o resto entra se a linha volta a pedir um comando | `pareamento: a edicao recusada na linha da cerimonia continua recusada quando a linha volta a pedir um comando`; `terminal: a marca da arvore sem reserva nao solta nem passa nada` — um aviso por caractere, e não um por vez |
| N169 | fora do SDK (passo 1, #297): o bit do histórico pelo modo que a cerimônia pede, e não pelo da linha que ficou | `pareamento: o aviso atrasado do fim nao muda a linha do nome nem a da senha do login` — a tecla entra no histórico com a linha pedindo a senha |
| N170 | fora do SDK (passo 1, L1): o arrendamento que a edição só renovou, solto | `terminal: so se solta o arrendamento que as edicoes recusadas deixaram` — a edição que começou do que um `ui.claim` renovou solta o dele |
| N171 | fora do SDK (passo 1, L1): sem a sequência — só a edição que tomou o arrendamento o solta, e duas recusadas em voo o deixam | `terminal: so se solta o arrendamento que as edicoes recusadas deixaram` |
| N172 | fora do SDK (passo 1, #297): o aviso da cerimônia mexe de novo nas linhas da troca da senha — só nelas; as do login ficam | `pareamento: o aviso atrasado do fim nao muda a linha do nome nem a da senha do login` — a linha da senha atual da troca vira uma linha de comando que engole |
| N173 | fora do SDK (resíduo do F1): a saída antecipada sem citação de volta — o registro sem citação não encolhe, e o anel corta o fim | hospedeiro: `auditoria::testes::a_descricao_encolhe_tambem_sem_citacao`, `a_descricao_encolhe_antes_do_motivo`, `o_corte_nao_deixa_palavra_pela_metade`, `o_detalhe_composto_guarda_a_citacao`; o motor: `a_recusa_do_manifesto_de_nome_longo_nao_e_sondagem`, `a_bifurcacao_de_nome_longo_liga_o_filho`, `a_decisao_de_pelo_acima_do_teto_e_do_processo`, `o_teto_de_nome_longo_alerta`; suíte x86, filtrada aos casos da mutação (891 de 895 na conta do harness, que dá os pulados como passados): `nsf: ve o codigo adulterado de quem tem descricao longa`, `nsf: a recusa do manifesto de quem tem descricao longa e do manifesto`, `nsf: a bifurcacao de quem tem descricao longa liga o filho`, `nsf: a decisao de quem tem descricao acima do teto e do processo` |
| N174 | fora do SDK (resíduo do F1): `Grafo::nasceu` sobrescreve o processo que já nasceu na época | hospedeiro: `grafo::testes::um_processo_nasce_uma_vez_so`; o motor: `a_bifurcacao_de_nome_longo_liga_o_filho` — a suíte não grava um nascimento repetido |
| N175 | fora do SDK (resíduo do F1): o `filho N` até o fio do pai aceito como nascimento | hospedeiro: `evento::testes::os_tipos`; o motor: `a_bifurcacao_de_nome_longo_liga_o_filho` — o registro cortado de um processo que o grafo não conhece; a suíte não grava um filho assim |
| N176 | fora do SDK (resíduo do F1): o texto cortado no meio da palavra, em qualquer fronteira de caractere | hospedeiro: `auditoria::testes::o_corte_nao_deixa_palavra_pela_metade`, `a_descricao_encolhe_tambem_sem_citacao`, `a_descricao_encolhe_antes_do_motivo`, `o_detalhe_composto_guarda_a_citacao`, `o_motivo_cortado_ainda_diz_a_falta`; suíte x86, filtrada aos casos da mutação (893 de 895 na conta do harness, que dá os pulados como passados): `auditoria: a citacao da decisao fica inteira acima do teto`, `chaves: a declaracao se ancora so na decisao de quem declara` |
| N177 | fora do SDK (resíduo do F1): `Falta::do_motivo` sem tirar a marca do corte | hospedeiro: `procedencia::testes::o_motivo_cortado_ainda_diz_a_falta`, `auditoria::testes::o_motivo_cortado_ainda_diz_a_falta`, `evento::testes::a_falta_de_quem_tem_descricao_longa` — a suíte não corta o motivo de procedência depois do encolhimento da descrição |
| N178 | fora do SDK (resíduo do F1): `Grafo::executa` ignora a abreviada de outro resumo — a troca que morre no mapeamento some | hospedeiro: `grafo::testes::a_abreviada_de_outro_resumo_e_uma_troca`; o motor: `a_troca_que_morre_no_mapeamento_fica_no_grafo` — a troca da suíte que falha depois do ponto sem volta vai com a descrição inteira |
| N179 | fora do SDK (resíduo do F1): a regra do firewall casada também pelo programa, no `security.provenance` | o motor: `o_firewall_casa_a_conexao_pelo_fio` — a suíte não barra no firewall um processo de descrição longa |
| N180 | fora do SDK (resíduo do F1): o corte sem a marca — o texto perde palavras e nada diz | hospedeiro: os cinco de `auditoria` da N176; suíte x86, filtrada aos casos da mutação (893 de 895 na conta do harness): `auditoria: a citacao da decisao fica inteira acima do teto`, `chaves: a declaracao se ancora so na decisao de quem declara` |
| N181 | fora do SDK (resíduo do F1, 7c): o editor `desconhecido` aceito no registro | hospedeiro: `registro::testes::o_editor_desconhecido_e_reservado` (sigilo), `producao::testes::o_editor_desconhecido_e_recusado` (xtask) — a imagem da suíte não tem o nome |
| N182 | fora do SDK (a CI 432): o `system.info` lê o civil antes de esperar a vez da hora — a leitura de antes da correção | suíte x86, filtrada aos casos `hora:` (895 de 896 na conta do harness, que dá os pulados como passados): `hora: o system.info le as rodadas e o civil num retrato so` — o leitor viu a rodada do pendente contada (`closed` 57, a última r67 `pendente`) sem o pendente dela (`pending_round` nulo) |
| N183 | fora do SDK (AE-5, o achado 4 do adversário do passo 1): a reserva do nome `desconhecido` de volta no leitor da linha do registro de chaves de atualização | hospedeiro: `registro::testes::a_busca_da_chave_de_atualizacao`, `a_linha_de_atualizacao_nao_tem_a_reserva` (sigilo); `slots::testes::o_registro_de_atualizacao_com_o_nome_reservado`, `producao::testes::a_chave_de_atualizacao_desconhecido_passa` (xtask) |
| N184 | fora do SDK (AE-5, item 1): o recolhimento sem limpar os zumbis — a morte só sai na colheita, como antes | suíte x86, filtrada (905 de 906 na conta do harness, que dá os pulados como passados): `fluxo: o zumbi solta o fluxo e o endpoint na morte, antes da colheita` |
| N185 | fora do SDK (AE-5, item 1): a colheita limpa de novo a morte que o zumbi já soltou | suíte x86, filtrada (905 de 906): o mesmo caso — duas limpezas da mesma morte |
| N186 | fora do SDK (AE-5, item 2): o fio da energia sem o gancho que a suíte segura (`energia::Segura`) | suíte x86, filtrada (905 de 906): `aviso: o desligamento avisa o fim` — o fio não parou ali |
| N187 | fora do SDK (AE-5, o F2 do adversário do AE-1): a execução da decisão do `exec` recalcula quem pede, em vez de ir em nome de quem o gate decidiu | suíte x86, filtrada (904 de 906): `fluxo: a execucao da troca vai em nome da decisao, com a sessao acabada no meio`, `fluxo: a troca de imagem que falha depois do ponto sem volta` |
| N188 | fora do SDK (AE-5, o F5): a volta "no meio" da troca de quem é ponta sem a execução adiada | suíte x86 num núcleo só (`DUKE_NUCLEOS=1`), filtrada (905 de 906): `fluxo: a troca de imagem ouve a ordem com outro no meio, tambem num nucleo so` |
| N189 | fora do SDK (AE-5, o achado 1): a entrega sem a conferência antes da conta da coordenação | suíte x86, filtrada (905 de 906): `terminal: a edicao que nao chega ao programa nao arrenda o campo` |
| N190 | fora do SDK (AE-5, o achado 1): a edição que só renovou e não chegou não passa a renovação à que ela continuou | suíte x86, filtrada (905 de 906): `terminal: a recusada solta o arrendamento mesmo com uma edicao que nao chegou` — a quinta de cinco quebra a sequência |
| N191 | fora do SDK (AE-5, o achado 2): o Enter que faz a linha pedir a pessoa sem recusar as edições a caminho | suíte x86, filtrada (904 de 906): `terminal: a tecla da pessoa depois do Enter, com a edicao a caminho, nao e CONFLICT`, `terminal: so se solta o arrendamento que as edicoes recusadas deixaram` |
| N192 | fora do SDK (AE-5, o achado 5): a soltura gravada como o `ui.release` do agente | suíte x86, filtrada (902 de 906): quatro dos casos que contam a soltura, os da rodada — `terminal: a edicao da arvore que corre com o Enter da pessoa nao entra na linha do nome`, `terminal: so se solta o arrendamento que as edicoes recusadas deixaram`, `terminal: a recusada solta o arrendamento mesmo com uma edicao que nao chegou`, `pareamento: a edicao da arvore que corre com o Enter do aceitar nao entra na linha da cerimonia`; o quinto, `terminal: a tecla da pessoa depois do Enter, com a edicao a caminho, nao e CONFLICT`, também a conta, e ficou fora do filtro |
| N193 | fora do SDK (AE-5, o achado 7): o consumo sem conferir de novo quem pediu a edição | suíte x86, filtrada (905 de 906): `terminal: a edicao de quem saiu da sessao e descartada` |
| N194 | fora do SDK (AE-5, o achado 8): a conferência do `xtask` só pela chamada com o caminho | hospedeiro: `testes_dos_nomes_protegidos::o_nome_sozinho_em_qualquer_forma` (xtask) |
| N195 | fora do SDK (AE-5, o item 4): o `definir` do físico sem a regra da linha da pessoa na seção que edita | suíte x86, filtrada (905 de 906): `interface: o definir do fisico confere a linha da pessoa onde edita` |
| N196 | fora do SDK (AE-5, o achado 3): o grafo do NSF compara a abreviada só pelo resumo | hospedeiro: `grafo::testes::o_mesmo_resumo_com_outro_de_ou_outro_editor_e_uma_troca`; o motor: `a_troca_para_o_codigo_de_fora_do_mesmo_resumo_fica_no_grafo` — a suíte não produz um código de fora com o resumo de um da imagem |
| N197 | fora do SDK (AE-5, o achado 6): o aviso de qualquer cerimônia muda a linha | suíte x86, filtrada (905 de 906): `pareamento: o aviso lido antes do fim da cerimonia nao muda a linha` |
| N198 | fora do SDK (AE-5, o achado 2 do adversário do passo 1b): o consumo da edição da árvore sem perguntar à contenção | suíte x86, filtrada (907 de 908): `terminal: a edicao de quem foi contido e descartada` |
| N199 | fora do SDK (AE-5, o achado 3 do adversário do passo 1b): o Enter escreve na linha o passo que leu, mesmo de antes do que ela mostra | suíte x86, filtrada (907 de 908): `pareamento: o passo lido antes do aviso nao volta a linha` — a volta dos códigos: a linha voltou à espera |
| N200 | fora do SDK (AE-5, o achado 3 do adversário do passo 1b): o Enter que leu a cerimônia viva a põe de volta na linha depois do fim | suíte x86, filtrada (907 de 908): `pareamento: o passo lido antes do aviso nao volta a linha` — a volta do fim: a cerimônia morta voltou à linha |
| N201 | fora do SDK (AE-5, o achado 3 do adversário do passo 1b): o aviso atrasado volta a linha a um passo de antes do que ela mostra | suíte x86, filtrada (907 de 908): `pareamento: o passo lido antes do aviso nao volta a linha` — a volta do aviso atrasado: a linha da senha voltou ao código |
| N202 | fora do SDK (AE-5, o achado 6 do adversário do passo 1b): o `xtask` deixa passar o `#[path]` no kernel fora da suíte | hospedeiro: `testes_dos_nomes_protegidos::o_atributo_de_caminho` (xtask) |
| N203 | fora do SDK (AE-5, o achado 6 do adversário do passo 1b): a conta que devolve o rastro fora dos nomes protegidos | hospedeiro: `testes_dos_nomes_protegidos::o_rastro_so_se_fabrica_nos_donos` (xtask) |
| N204 | fora do SDK (AE-5, o achado 2 do adversário do passo 1b): a soltura do arrendamento de quem foi contido com o motivo de quem saiu da sessão | suíte x86, filtrada (907 de 908): `terminal: a edicao de quem foi contido e descartada` — a conta que correu com a contenção, depois do reforço |
| N205 | fora do SDK (AE-5, o achado 1 do adversário do passo 1c): o consumo aceita a edição da pessoa cuja sessão acabou | suíte x86, filtrada (909 de 910): `terminal: a edicao da pessoa que saiu da sessao e descartada` |
| N206 | fora do SDK (AE-5, o achado 1 do adversário do passo 1c): a reserva de uma edição de pessoa sem a sessão dela passa | suíte x86, filtrada (909 de 910): `terminal: a edicao da pessoa que saiu da sessao e descartada` — a reserva sem sessão |
| N207 | fora do SDK (AE-5, o achado 2 do adversário do passo 1c): o `xtask` só vê o `path` logo depois do `#[` | hospedeiro: `testes_dos_nomes_protegidos::o_caminho_de_outro_arquivo_em_qualquer_forma` (xtask) — o `cfg_attr` e o `r#path` |
| N208 | fora do SDK (AE-5, o achado 3 do adversário do passo 1c): o aviso da cerimônia escreve o bit do histórico de novo depois de soltar a trava | suíte x86, filtrada (909 de 910): `pareamento: o aviso dos codigos nao apaga o bit que o Enter ligou` — a tecla da senha foi ao histórico |
| N209 | fora do SDK (CI 437): a troca que chega ao fim grava também uma execução da decisão | suíte x86, filtrada (904 de 910): os quatro modos da ordem presa — `fluxo: a troca de imagem com fluxo e a ordem com outro fio`, `fluxo: a troca de imagem com a ordem tomada no meio`, `fluxo: a troca de imagem adiada abre a janela das interrupcoes`, `fluxo: a troca de imagem adiada da a vez a quem tem a ordem` —, `fluxo: a troca de imagem ouve a ordem com outro no meio, tambem num nucleo so` e `fluxo: a troca grande com escritas sem parar, medida` |
| N111, de novo | fora do SDK (CI 437): a volta adiada sem a execução da decisão, contra a conta nova | suíte x86, filtrada (907 de 910): `fluxo: a troca de imagem com fluxo e a ordem com outro fio`, pelo sinal novo, `fluxo: a troca de imagem com a ordem tomada no meio` e `fluxo: a troca de imagem ouve a ordem com outro no meio, tambem num nucleo so` |
| N210 | fora do SDK (#310): o cabeçalho da imagem na memória comparado com o `ImageBase` que o carregador reescreveu | hospedeiro: `firmware::testes::o_cabecalho_pe_sem_o_image_base`, `os_modulos_do_arquivo_do_firmware`, `onde_estavam_os_processadores_da_ci_436`, `a_pilha_nao_gasta_as_procuras_com_os_dados` e `a_pilha_no_fim_da_memoria` (xtask) — o da CI 436 depois do reforço: os módulos dele passaram a vir com o `ImageBase` do arquivo, e não com o da memória |
| N211 | fora do SDK (#310): a imagem de baixo aceita sem conferir que ela vai até o endereço | hospedeiro: `firmware::testes::a_imagem_pelo_cabecalho_abaixo`, `o_codeview_primeiro_e_as_linhas_sem_nome` e `a_pilha_nao_gasta_as_procuras_com_os_dados` (xtask) |
| N212 | fora do SDK (#310): o caminho do `NB10` lido quatro bytes antes | hospedeiro: `firmware::testes::o_nome_no_codeview` (xtask) — depois do reforço: com um caminho de diretórios, o nome lido do lugar errado ainda acabava no mesmo último componente, e a mutação sobreviveu; o teste ganhou nomes sem diretório e letras, e não zeros, entre a assinatura e o caminho |
| N213 | fora do SDK (#310): o caminho do `MTOC` lido quatro bytes depois | hospedeiro: `firmware::testes::o_nome_no_codeview` (xtask) |
| N214 | fora do SDK (#310): os valores iguais e vizinhos da pilha repetidos | hospedeiro: `firmware::testes::onde_estavam_os_processadores_da_ci_436` (xtask) |
| N215 | fora do SDK (#310): o `\r` escapado do `info registers` deixado no texto | hospedeiro: `firmware::testes::os_processadores_pelo_info_registers` (xtask) |
| N216 | fora do SDK (#310): os dados da seção GUID lidos do fim do cabeçalho, e não de onde o `DataOffset` diz | hospedeiro: `firmware::testes::os_modulos_do_arquivo_do_firmware` (xtask) — a seção do teste tem quatro bytes a mais no cabeçalho, como a do CRC32: sem eles, o fim do cabeçalho e o `DataOffset` coincidem |
| N217 | fora do SDK (#310): a procura da pilha que não acha imagem marca vazia só a página do valor | hospedeiro: `firmware::testes::a_pilha_nao_gasta_as_procuras_com_os_dados` (xtask) — as procuras acabam antes do retorno para o núcleo do DXE |
| N218 | fora do SDK (#310): o valor da pilha que cai nos dados de uma imagem tomado por retorno | hospedeiro: `firmware::testes::onde_estavam_os_processadores_da_ci_436` (xtask) |
| N219 | fora do SDK (#310): a pilha que não se lê inteira — no fim da memória — não se lê nada | hospedeiro: `firmware::testes::a_pilha_no_fim_da_memoria` (xtask) |
| N220 | fora do SDK (#310): o arquivo de enchimento do volume — o nome todo em `0xff` — tomado pelo espaço livre, e o resto do volume perdido | hospedeiro: `firmware::testes::os_modulos_do_arquivo_do_firmware` (xtask) — achado ao ler o AAVMF, que tem um logo depois do `PeiCore` |
| N221 | fora do SDK (#313): o IDE de onde o firmware do x86 boota sem `bootindex` | hospedeiro: `testes::so_o_disco_do_boot_leva_a_ordem_de_boot` (xtask) — o x86 com o disco no virtio sem ordem nenhuma |
| N222 | fora do SDK (#313): o `disco0` sem `bootindex` quando o firmware boota dele — o NVMe do x86, o disco do ARM | hospedeiro: `testes::so_o_disco_do_boot_leva_a_ordem_de_boot` (xtask) — o x86 com o NVMe sem ordem |
| N223 | fora do SDK (#313): o x86 com o disco no virtio bootando pelo `disco0`, sem o IDE | hospedeiro: `testes::so_o_disco_do_boot_leva_a_ordem_de_boot` (xtask) — a ordem no virtio, e não no IDE |
| N224 | fora do SDK (#313): a máquina sem firmware — o ARM pelo `-kernel` — com ordem de boot | hospedeiro: `testes::so_o_disco_do_boot_leva_a_ordem_de_boot` (xtask) |
| N225 | fora do SDK (#313): a conferência da linha aceita mais de um dispositivo com ordem, tomando o primeiro | hospedeiro: `testes::a_ordem_de_boot_errada_e_recusada` (xtask) — o PXE na placa de rede |
| N226 | fora do SDK (#313): a conferência não olha de que unidade é o dispositivo com a ordem | hospedeiro: `testes::a_ordem_de_boot_errada_e_recusada` (xtask) — a ordem no disco do kernel, e não no do firmware |
| N227 | fora do SDK (#313): a conferência aceita ordem numa máquina sem firmware | hospedeiro: `testes::a_ordem_de_boot_errada_e_recusada` (xtask) |
| N228 | fora do SDK (#313): a conferência aceita a ordem do disco do boot com outro valor | hospedeiro: `testes::a_ordem_de_boot_errada_e_recusada` (xtask) — `bootindex=1` |
| N229 | fora do SDK (#314): o fim do disco hostil sem esperar o fio do servidor — o `join` tirado do `Drop` | hospedeiro: `disco_hostil::testes::o_fim_espera_a_conexao_em_curso` (xtask) — o fio ainda segura o estado depois do `Drop`; sem essa conferência, a descarga atendida antes do fim não está no arquivo quando ele volta |
| N230 | fora do SDK (CI 439): toda recusa — `DENY_` em qualquer lugar da resposta — marcando a máquina para o fim dela perguntar o motivo da persistência | hospedeiro: `persistencia::testes::a_recusa_de_revogacao_pede_o_motivo` (xtask) — a recusa por permissão marca |
| N231 | fora do SDK (CI 439): o estado e o motivo da persistência lidos com o leitor de campo simples, e não pelo JSON | hospedeiro: `persistencia::testes::a_recusa_de_revogacao_pede_o_motivo` (xtask) — o motivo sai cortado na primeira vírgula |

## Medidas

O kernel de release, nos segmentos carregados (a soma do `filesz` dos
`LOAD`), contra o fim do DN-2:

| | DN-2 | DN-3 | diferença |
|---|---:|---:|---:|
| x86_64 | 5 138 155 | 5 312 619 | +174 464 (+3,4%) |
| aarch64 | 4 298 347 | 4 459 187 | +160 840 (+3,7%) |

Na memória (a soma do `memsz`), +174 616 bytes no x86_64 e +133 728 no
aarch64. A medida é do código final do DN-3, depois das cinco rodadas do
agente adversário.

A bancada `cargo xtask sdk` na CI 410 — o código final, QEMU sem KVM,
dois núcleos por máquina, as duas no mesmo hospedeiro de quatro. "Laço" é
o modelo e o `eco-malha`, um processo e uma espera no canal; "bloqueante"
é o `remetente` e o `recebedor` do DN-2, cada pedido esperando. As vazões
contam os dois sentidos. Os pares da mesma arquitetura e os cruzados
correm em jobs — e hospedeiros — diferentes, e os números só se comparam
dentro de cada par: o hospedeiro dos pares da mesma arquitetura andou
perto do dobro do dos cruzados em tudo, também no bloqueante do DN-2, que
o DN-3 não mudou.

| Par | NB05: 40 KiB ida e volta | NB02: 1 MiB de cada lado | Laço entre os Dukes | Laço local | Bloqueante entre os Dukes | Do aviso à operação (média, origem / destino) | Pior | O par inteiro |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| x86_64→x86_64 | 1,27 s | 93 KiB/s | 84 KiB/s | 134 KiB/s | 108 KiB/s | 55 / 56 ms | 0,83 s | 496 s |
| aarch64→aarch64 | 1,11 s | 106 KiB/s | 95 KiB/s | 145 KiB/s | 123 KiB/s | 50 / 51 ms | 0,70 s | 355 s |
| x86_64→aarch64 | 2,31 s | 52 KiB/s | 44 KiB/s | 57 KiB/s | 56 KiB/s | 100 / 132 ms | 1,33 s | 849 s |
| aarch64→x86_64 | 2,45 s | 60 KiB/s | 44 KiB/s | 59 KiB/s | 62 KiB/s | 86 / 124 ms | 1,53 s | 635 s |

Cada leitura e cada escrita continua sendo uma decisão do gate e um
registro da auditoria — o número mede isso, e não o transporte. O laço
fica de 21% a 29% abaixo do bloqueante entre os Dukes, e a comparação não
é limpa: no NB01 o cliente remoto divide a máquina B — e o `eco-malha` —
com o cliente local, ao mesmo tempo, e o bloqueante do NB06 corre
sozinho; e o laço soma a volta pelo canal — o aviso publicado, o fio
acordado no canal, a operação pedida ao gate —, que na bancada leva em
média de 50 a 132 ms com os dois emuladores disputando o hospedeiro. Em
troca, um processo serve vários fluxos, a janela e o pseudo-terminal numa
espera só. Os avisos de cada máquina ao fim do NB05, do NB01 e do NB02 (o
`security.metrics`, desde o boot): de 407 a 447 publicados e de 439 a 473
juntados na origem; de 753 a 1 016 publicados e de 1 319 a 1 405 juntados
no destino, que também tem as duas pontas do cliente local do NB01 — e o
canal nunca teve mais de um aviso do mesmo objeto.

## Limites conhecidos

Os residuais da validação final — nenhum é bypass de autoridade:

- **Os nomes do laço são previsíveis.** A tabela de canais não enche
  mais: são 190 — dois por fio que o escalonador comporta, o pior caso dos
  processos —, estáticos, ~409 KB de RAM fixa; cada processo escuta no
  máximo 2, contados na mesma seção crítica que insere, e nenhum
  principal, nem um conjunto deles, ocupa todos. Mas o `Laco::novo` tenta
  16 nomes (`laco-<id>`, `laco-<id>-1`…), que são previsíveis, e quem os
  tomar todos — 8 processos de uma sessão de operador, com 2 canais cada
  — impede o laço daquele processo. O canal sem nome, que fecharia isso,
  seria crescimento do contrato (decisão revisada, DS-2), e não está
  feito.
- **O teto das designações acabadas** (8 por processo) larga primeiro a
  de menor chave — os endpoints antes das pontas —, e pode largar o `FIM`
  devido de um objeto de que o dono nunca ouviu aviso. Só age com o canal
  cheio, ou com avisos tirados da fila sem operação, e mais de 8 objetos
  acabados do mesmo processo; a operação seguinte sobre o objeto ouve o
  fim.
- **A retirada** (`fabric.withdraw`) larga a designação antes de acordar
  quem espera; mas outro fio que conte as marcas da malha entre o fecho
  do endpoint e o largar ainda pode avisar `FIM` a quem retirou — um
  aviso a mais, sem efeito: a operação seguinte diz que o endpoint não
  existe.
- **A conta atrasada** de outro núcleo não publica o nível de antes de uma
  operação do dono (NS48) — salvo se chega à trava entre a operação e o
  consumo do aviso, a janela em que a operação ainda acorda quem espera e
  grava o que fez: então ela ainda pode dizer o que a operação acabou de
  mudar — o fim que ela ouviu, o dado que ela leu. Um aviso a mais, sem
  efeito: a operação seguinte diz o que há.
- **Os endpoints persistem na troca de imagem** (`exec`), como sempre
  persistiram na malha; as designações e os avisos na fila, não.
- **O filtro do que é novo é por objeto**: ele guarda o nível inteiro que a
  operação recusada encontrou, e não só os bits dela. Uma entrega que chega
  entre o aviso do pedido e o aceite recusado pela cota só avisa no rearme
  — embora a recepção passasse —; e a recepção que passa desfaz o
  espaçamento do aceite recusado — o pedido avisa de novo, uma vez por
  entrega. Nenhum dos dois gira: o primeiro espera no máximo o rearme; o
  segundo é uma tentativa a mais por entrega. A vaga, do mesmo jeito,
  esquece o nível recusado inteiro dos endpoints do processo, e não só o
  pedido: o fim de um fluxo que contava na cota dele — um que ele abriu,
  ou que aceitou — traz de volta, num aviso na hora, o que outra operação
  recusada dele tinha encontrado, também o que nada tem com a cota (a
  entrega que a recepção recusada pela taxa encontrou) — uma tentativa a
  mais por vaga, sem giro: a recusa que responde a esse aviso espaça de
  novo, e a mesma vaga não avisa duas vezes (NS50). Só não espaça a
  recusa que vem antes de o aviso da vaga sair — a vaga chegou com um
  aviso ainda não consumido, que é ela que consome (NS43), também com o
  rearme passando no meio (NS53) —, e o aviso da vaga sai logo depois
  dela, uma vez; a recusa no meio da qual ele já saiu o consome e espaça,
  e o evento fica no canal (NS51). O transbordo das marcas — mais de 64
  objetos distintos marcados entre duas passadas — não esquece nível
  recusado nenhum: a passada que avalia tudo faz a conta de sempre, e só a
  vaga o esquece, nos endpoints do processo dela — a marca dela, à parte,
  não se perde no transbordo (NS52, NS54). Essa marca tem teto —
  uma por fio que o escalonador comporta —, que não é alcançado: toda
  passada leva as marcas todas, quem marca passa logo depois, e o fim dos
  fluxos de um processo que acabou vem com uma passada, antes de o fio
  dele sair do escalonador. Se fosse alcançado, a marca cairia com o
  transbordo, e o pedido esperaria o rearme da recusa — sem que se
  dissesse nada a ninguém.
- **A recusa pela forma do pedido** — o `notify` que não é canal do
  processo, o `wait` que não cabe, o id que não é de um fluxo dele — não
  chega ao objeto e não consome o aviso: o objeto fica com o aviso não
  consumido, e só o próprio dono fica sem notícia dele até operar direito.

## O que não existe

- **Argumentos.** Um programa não recebe argumentos: o que ele deve fazer
  vem do armazém (um arquivo de pedido, como o do `copiador`), da janela,
  ou de uma entrega.
- **Fios de usuário.** Um processo, um fio, uma espera: o laço.
- **Pacotes.** Não há gerenciador de pacotes, repositório, dependências
  entre programas nem atualização de programas: o programa é um arquivo
  selado.
- **Subcanais, multiplexação e retomada.** Um fluxo é um canal; os tetos
  são de fluxos. Um fluxo que acaba não volta, e nada dele persiste.
- **Handoff, continuidade, recursos remotos, descoberta e presença.** Cada
  um exige uma decisão própria, e nenhum foi tomado aqui.
