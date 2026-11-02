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

e nunca `aviso → operação`. O caso da revogação entre o aviso e a leitura
prova (NS11), e a mutação N16 o confere.

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
kernel não conhece ele **recusa** (`INVALID_ARGUMENT`), nunca ignora; o
programa ignora, no que recebe, o que não conhece — um bit do aviso que
esta versão do runtime não sabe não muda nenhuma resposta de
[`Prontidao`](../programas/src/laco.rs). Remover é só numa versão maior,
por decisão própria, e o removido é recusado. Um kernel tem uma versão
viva.

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
nada é designado. Só um processo designa: só um processo oferece, abre e
aceita, e o pedido de uma pessoa ou de um agente é recusado como sempre,
com o mesmo código com ou sem `notify` (NS14).

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

Os pedidos "agora" — `Fluxo::ler_agora`, `Fluxo::escrever_agora`,
`aceitar_avisando` — não esperam dado nem espaço (levam a espera mínima do
plano de dados, para o caminho da auditoria cheio poder segurá-los em vez
de cobrar a taxa). O que não coube na escrita espera numa
[`EscritaPendente`](../programas/src/fluxo.rs), que escoa quando o
`GRAVAVEL` vem. As variantes com espera do DN-2 continuam valendo, e um
mesmo processo pode ter um fluxo com o aviso e outro sem.

**O fim e o fecho.** `Fluxo::terminar` termina o sentido daqui: o outro
lado lê o resto e o fim (`LEGIVEL`). Quando o fluxo acabou de vez para o
dono — o outro lado fechou, foi revogado, o processo dele morreu, o
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
| a política tira a permissão entre o aviso e a operação | a operação é recusada pelo gate, com o código dela (NS11, NS15) |
| o outro lado fechou | `FIM`; a próxima operação, `CONFLICT` `fechado pela ponta` |
| o processo do outro lado morreu | `FIM`; `CONFLICT` `o processo acabou` |
| o dispositivo suspenso, esquecido ou revogado | `FIM`; `CONFLICT` com o motivo do dispositivo (NS23) |
| o Duke desligando | `FIM` em cada objeto designado (NS22) |
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
   adulterado ou de editor estranho, é recusado na troca de imagem
   (`CODE_UNSIGNED`, `CODE_TAMPERED`, `CODE_UNTRUSTED`). Um editor novo é
   uma imagem nova.

O `cargo xtask sdk-fora` faz os passos 1 a 4 com o modelo, numa cópia em
`target/sdk-fora/` — fora de todo workspace do repositório —, e é o job
"SDK fora do repositório" da CI (NX01–NX03). A bancada da suíte publica o
modelo selado, e as variantes que o Duke recusa, como publica o `vindo`; o
NS28 o instala e roda.

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
