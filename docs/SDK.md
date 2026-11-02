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
`ENTRADA`), e o pseudo-terminal também: um processo, uma espera.

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
  consumido, nada mais desse objeto é publicado — nem o `FIM`;
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
- `FIM` sai uma vez, e só com o aviso anterior consumido. Depois da
  operação do dono que ouviu o fim, nada mais é publicado sobre o objeto,
  e a designação sai;
- **um aviso de cada objeto no canal**: a operação do dono consome o aviso
  mesmo que o evento ainda esteja na fila do canal — o programa que lê
  várias vezes seguidas, sem voltar ao laço, rearma a cada leitura. O
  aviso seguinte do mesmo objeto, com o anterior ainda na fila, **junta-se**
  a ele (os bits somados) em vez de ocupar outro lugar: o canal nunca tem
  dois eventos do mesmo objeto, e um fluxo agitado não enche o canal de
  avisos velhos (NS01b).

O endpoint avisa `ENTREGA` enquanto houver entrega ainda não recebida: um
programa que oferece com o aviso e não usa entregas ainda assim chama
`malha::receber` quando o bit vem — ou o aviso volta a cada operação.

### O canal cheio, a morte, a troca de imagem

- O canal guarda 64 eventos. Com ele cheio, o aviso fica **devido** e o
  coletor o entrega depois, sem perder o objeto nem duplicar o aviso.
- O canal que ninguém mais escuta — o processo fechou o descritor, ou
  morreu — larga as designações dele.
- A troca de imagem (`exec`) larga as designações **antes** do resto: a
  imagem nova não ouve os avisos da anterior. Os endpoints persistem, como
  sempre persistiram; a imagem nova oferece com o aviso de novo, se quiser.
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
registro do comando que a pediu (com o canal), e cada operação depois do
aviso está no registro dela. As medidas vão ao `security.metrics`, em
`mesh_notices`: as designações vivas (`designations`), os avisos
publicados (`published`), os juntados a um do mesmo objeto ainda na fila
(`merged`), as mudanças que não avisaram porque já havia um aviso não
consumido (`coalesced`), os que acharam o canal cheio (`full_channel`) e
os entregues depois (`delivered_later`), as designações largadas com o
canal (`dropped`), os `notify` recusados (`refused`) e a latência do aviso
publicado até a operação do dono que o consome (`to_operation_samples`,
`to_operation_avg_ns`, `to_operation_max_ns`).

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

**O fim e o fecho.** `Fluxo::terminar` termina o sentido daqui: o outro
lado lê o resto e o fim (`LEGIVEL`). Quando o fluxo acabou de vez para o
dono — o outro lado fechou (lido o que ele mandou), foi revogado, o
processo dele morreu, o
dispositivo foi suspenso ou esquecido —, a ponta avisa `FIM`, e a próxima
operação ouve `CONFLICT` com o motivo (`fechado pela ponta`, `revogado`,
`o dispositivo foi suspenso`…).

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
  não dá escrita nenhuma.
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
| o canal de eventos cheio | nada: o aviso fica devido, e chega depois |

## As cotas

| O quê | Quanto |
|---|---|
| canais de eventos na máquina | 32 |
| canais escutados por processo | 2 (o laço e um de folga) |
| eventos guardados por canal | 64 |
| avisos não consumidos por objeto | 1 |
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

- **No hospedeiro** (NH01–NH13): a conta pura do aviso
  (`politica::aviso`) — a borda que publica uma vez, a operação que
  rearma, o espaço só para quem o quer, o fim uma vez, o canal cheio, o
  canal sem ouvinte, a codificação e o evento que só tem o tipo, o número e
  os bits —; o quadro (`protocolo::quadro`); no xtask, o selo e a lista
  do contrato, com a conferência que acusa o parâmetro tirado; e a
  prontidão que o kernel pergunta, da ponta (`politica::fluxo`, NH12) e do
  endpoint (`politica::malha`, NH13).
- **Na suíte**, nas duas arquiteturas: 26 casos `aviso:` (NS01–NS25 e o
  NS01b) e 6 casos `sdk:` (NS26–NS31). O programa `avisado` só espera no
  canal dele e diz no log cada aviso que chega; a suíte dita os passos a
  ele — o caminho inteiro pelo runtime — ou pede **como** ele, pela mesma
  função do gate, nos passos que precisam ser exatos. O que se confere é o
  que o kernel publicou, quando e quantas vezes, e que cada operação depois
  de um aviso continua sendo um pedido decidido pelo gate.
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
  `conversa` com a pessoa digitando nas duas; a revogação no meio de um
  fluxo.

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

| | Mutação | Reprovada por |
|---|---|---|
| N01 | a designação sem conferir que o processo escuta o canal | NS08 |
| N02 | o descritor que não é canal, ignorado em silêncio | NS09 |
| N03 | a recusa do gate que ainda designa o endpoint do pedido | NS10, depois do reforço |
| N04 | o primeiro byte do fluxo no campo `b` do aviso | NS12 |
| N05 | o aviso da ponta no canal do par | NS13 |
| N06 | sem coalescência: toda mudança publica | NH01, NH05; NS01 |
| N07 | sem rearme depois da operação do dono | NH02, NH03; NS01, NS26 |
| N08 | o rearme sem reavaliar a prontidão | NS01b |
| N09 | o `GRAVAVEL` nunca publicado | NH03, NH06; NS02, NS06 |
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

## Medidas

O kernel de release, nos segmentos carregados (a soma do `filesz` dos
`LOAD`), contra o fim do DN-2:

| | DN-2 | DN-3 | diferença |
|---|---:|---:|---:|
| x86_64 | 5 138 155 | 5 284 163 | +146 008 (+2,8%) |
| aarch64 | 4 298 347 | 4 445 075 | +146 728 (+3,4%) |

Na memória (a soma do `memsz`), +145 972 bytes no x86_64 e +131 904 no
aarch64.

A bancada `cargo xtask sdk` na CI 401 — QEMU sem KVM, dois núcleos por
máquina, as duas no mesmo hospedeiro de quatro. "Laço" é o modelo e o
`eco-malha`, um processo e uma espera no canal; "bloqueante" é o
`remetente` e o `recebedor` do DN-2, cada pedido esperando. As vazões
contam os dois sentidos.

| Par | NB05: 40 KiB ida e volta | NB02: 1 MiB de cada lado | Laço entre os Dukes | Laço local | Bloqueante entre os Dukes | Do aviso à operação (média, origem / destino) | Pior | O par inteiro |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| x86_64→x86_64 | 2,66 s | 52 KiB/s | 37 KiB/s | 56 KiB/s | 56 KiB/s | 99 / 130 ms | 1,43 s | 914 s |
| aarch64→aarch64 | 2,17 s | 62 KiB/s | 48 KiB/s | 69 KiB/s | 66 KiB/s | 83 / 107 ms | 1,46 s | 593 s |
| x86_64→aarch64 | 2,32 s | 53 KiB/s | 43 KiB/s | 74 KiB/s | 61 KiB/s | 99 / 101 ms | 1,43 s | 824 s |
| aarch64→x86_64 | 2,59 s | 61 KiB/s | 43 KiB/s | 56 KiB/s | 62 KiB/s | 85 / 128 ms | 1,93 s | 610 s |

Cada leitura e cada escrita continua sendo uma decisão do gate e um
registro da auditoria — o número mede isso, e não o transporte. O laço
fica de 27% a 34% abaixo do bloqueante entre os Dukes, e a comparação não
é limpa: no NB01 o cliente remoto divide a máquina B — e o `eco-malha` —
com o cliente local, ao mesmo tempo, e o bloqueante do NB06 corre
sozinho; e o laço soma a volta pelo canal — o aviso publicado, o fio
acordado no canal, a operação pedida ao gate —, que na bancada leva em
média de 83 a 130 ms com os dois emuladores disputando o hospedeiro. Em
troca, um processo serve vários fluxos, a janela e o pseudo-terminal numa
espera só. Os avisos de cada máquina ao fim do NB05, do NB01 e do NB02 (o
`security.metrics`, desde o boot): de 419 a 441 publicados e de 432 a 462
juntados na origem; de 798 a 1 006 publicados e de 1 354 a 1 443 juntados
no destino, que também tem as duas pontas do cliente local do NB01 — e o
canal nunca teve mais de um aviso do mesmo objeto.

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
