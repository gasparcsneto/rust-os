# Armazenamento nativo

## O que é

Os programas, os agentes e as pessoas do Duke guardam dados no **armazém**:
uma árvore de arquivos e diretórios montada em `/armazem`, gravável, com
versão por objeto, arrendamento para quem edita, cota por dono, e cada
mudança confirmada só depois de persistida. Não há um segundo sistema de
autorização para ele, nem uma segunda API: as operações são comandos do
registro, chegam pelo mesmo `pedir` (ou pelo canal, ou pelo interpretador),
passam pelo mesmo gate e vão para a mesma cadeia de auditoria.

O caminho de toda mutação é o da regra da arquitetura:

```text
identidade → sessão → autorização (gate) → coordenação (arrendamento)
           → operação (o lote) → auditoria → persistência (o commit)
```

## Os conceitos, e onde cada um mora

Eles não se misturam. Cada um tem um lugar, uma pergunta e uma recusa.

| Conceito | A pergunta | Onde mora | A recusa |
|---|---|---|---|
| **Autorização** | esta identidade pode escrever (ou ler)? | `autorizacao::autorizar` — a permissão `fs.write` (ou `fs.read`) no papel, ∩ manifesto do programa | `DENY_PERMISSION`, `DENY_ROLE`… |
| **Alcance de caminho** | **cada** caminho do pedido está dentro da autoridade efetiva? | a mesma decisão, sobre todos os recursos do pedido: o caminho, o destino de um rename, cada caminho de um lote | `DENY_RESOURCE` |
| **Reconfirmação** | a autoridade decidida ainda vale no ponto de commit? | `autorizacao::reconfirmar`, com a ordem das gravações na mão | a recusa de agora (`DENY_SESSION`, `DENY_ROLE`…) |
| **Arrendamento** | alguém tem agora o direito exclusivo de editar este objeto? | a tabela de `coordenacao`, recurso `fs:<caminho>` — só o arrendamento | `CONFLICT`, com `"conflict":"lease"` |
| **Versão** | a mutação é contra o estado que quem pede leu? | o armazém: cada nó tem a versão da última mudança | `CONFLICT`, com `"conflict":"version"` e a versão de agora |
| **Cota** | o dono tem lugar para isto? | o armazém, com a cota que a política dá ao papel de quem pede | `DENY_QUOTA` |
| **Persistência** | a mudança está no disco? | o volume do armazém e o journal de estado — o commit é o registro de estado que confirma o lote | `ERROR`, e nada muda |
| **Auditoria** | quem decidiu o quê, e o que aconteceu? | a decisão do gate; e o que o comando fez, com o número da decisão, **no mesmo registro** do journal de estado que o commit | — |

## A partição própria

O conteúdo dos arquivos e os metadados deles moram numa partição só do
armazém — tipo GPT `4A1F7C3B-92D6-4E5A-8B07-C3E91D6F2A58`, `duke-armazem` —,
e não no journal de estado. O driver do disco tem duas janelas de escrita,
fixadas uma vez no boot a partir da GPT e que não se cruzam: a do estado,
que só a persistência usa, e a do armazém, que só o volume usa (o `xtask`
confere as duas regras no código, e o driver confere a janela em cada
escrita). Encher o volume não enche o journal das credenciais, e um volume
estragado não derruba o estado de autoridade.

```text
setor 0                      setores_do_diario                  setores
| journal dos metadados      | área de dados: blocos de 4 KiB   |
| (duas regiões, como o de   | (4080 de carga + etiqueta        |
|  estado, chave própria)    |  Poly1305), nunca reescritos     |
|                            |  enquanto um arquivo os tem      |
```

- O **journal dos metadados** é o pacote `diario`, com uma chave derivada
  da do Duke por outro rótulo (`Duke armazem v1`): um registro de um não
  abre no outro. Cada registro é um **lote** de mudanças; a abertura diz a
  geometria do volume; a base de uma compactação leva os nós e a próxima
  versão.
- Cada **bloco** é cifrado com XChaCha20-Poly1305: o nonce é o id do
  conteúdo (16 bytes, sorteado por escrita) e o índice lógico do bloco no
  arquivo; o dado associado é o id do volume. Um bloco trocado de lugar, de
  arquivo ou de volume não abre.
- O **mapa** dos blocos livres não vai para o disco: o boot o refaz dos
  metadados. O conteúdo novo vai sempre para blocos livres (cópia na
  escrita), e um bloco que nenhum metadado confirmado aponta está livre.

O volume é validado no boot: a partição tem de existir, ter ao menos
8 MiB, e a geometria gravada na abertura tem de ser a dela. No primeiro
boot de um disco novo o volume é criado (a abertura é confirmada no
journal de estado); depois, ele só vale se o journal dele chega exatamente
ao registro que o journal de estado confirmou.

## O ponto de commit

O journal do armazém não fala com o TPM. Quem o ancora é o journal de
estado: a entrada `ARMAZEM_CONFIRMADO [id, setores, setores_do_diario,
âncora, elo]` diz qual registro do journal do armazém vale. Um lote se
grava assim, tudo com a ordem das gravações na mão
(`persistencia::em_ordem`):

1. os blocos do conteúdo novo, em blocos livres;
2. o registro do lote no journal do armazém, com a âncora seguinte dele;
3. a descarga do disco — os blocos e o registro, juntos;
4. o registro no journal de estado com `ARMAZEM_CONFIRMADO` e a auditoria
   da execução: escrito, descarregado, e o contador do TPM avançado.
   **Este é o ponto de commit.**
5. só então o lote vale em memória, e os blocos que ele deixou de usar
   voltam a ser livres.

Uma queda antes do passo 4 deixa no volume blocos e um registro que o
journal de estado não confirma: no boot o percurso do journal do armazém
para na âncora confirmada (`diario::percorrer_ate`), o escritor continua
por cima, e os blocos estão livres. **Nada de um lote pela metade parece
confirmado.** Uma queda depois do passo 4 é o lote inteiro: o journal de
estado o confirma, e o do armazém o tem, porque foi descarregado antes.

Um volume devolvido a uma cópia anterior, ou trocado por outro, não chega
à âncora e ao elo confirmados: o armazém fica indisponível com o motivo, e
o estado de autoridade segue. Um journal de estado devolvido a uma cópia
anterior é recusado pelo TPM, como sempre.

## A ordem de uma mutação

1. o gate decide, sobre **cada** caminho do pedido (autorização ∩
   manifesto, e o alcance), e grava a decisão na auditoria — o handler
   recebe o número dela junto com a autoridade;
2. com a ordem das gravações na mão:
   1. a persistência e o volume estão disponíveis? — senão `ERROR`;
   2. **reconfirmação**: a sessão, a credencial, o papel e a política de
      agora ainda dão a autoridade decidida? — senão a recusa de agora, e
      nada muda. Uma revogação, um logout ou uma política nova que chegou
      entre a decisão e o commit vale: as revogações também passam pela
      ordem das gravações, então ou vieram antes da reconfirmação — e a
      mutação é recusada — ou vêm depois do commit;
   3. o arrendamento de outro titular em qualquer caminho tocado — num
      rename, em qualquer caminho abaixo da origem ou do destino — recusa;
   4. o conteúdo novo vai para blocos reservados;
   5. o armazém prepara o lote inteiro — versões, lugares, tipos, a cota,
      o teto dos metadados —, sem aplicá-lo;
   6. a auditoria registra o que o comando vai fazer (`lote a gravar: N
      operacoes, versoes a..b`), em nome de quem o gate autorizou;
   7. o commit, como acima;
3. cada recusa depois do gate vai para a auditoria como o resultado do
   comando autorizado, com o número da decisão.

Por que um registro da execução, e não só a decisão: a decisão é gravada
pelo gate antes de o handler ter a ordem das gravações na mão, e o coletor
da auditoria pode levá-la ao disco sozinha nesse meio tempo. O registro da
execução é feito com a ordem na mão, e vai no mesmo registro de estado que
o commit.

## Lotes

`fs.batch` faz até 32 operações (`write`, `append`, `delete`, `mkdir`,
`rmdir`, `rename`) num lote só: **tudo ou nada**. Cada operação vê o efeito
das anteriores; uma que não passa recusa o lote inteiro, e a resposta diz
qual (`op`). O gate decide cada caminho do lote — um fora do alcance recusa
o lote antes de qualquer coisa. Um lote é um registro do journal do
armazém, um registro do journal de estado e **um** avanço do contador do
TPM, quantas operações tiver. `fs.write`, `fs.mkdir` e os outros são lotes
de uma operação.

## Versão

Cada mudança recebe a versão seguinte de um contador **do armazém
inteiro**, que só cresce e é persistido. A versão de um nó é a da última
mudança nele; um caminho sem nó tem versão 0. Um objeto apagado e criado de
novo não volta a uma versão que alguém já leu.

- `fs.write` com `expect_version: 0` cria — e recusa se já existe;
- com `expect_version: N` substitui — e recusa se a versão não é `N`;
- `fs.append`, `fs.delete`, `fs.rmdir` e `fs.rename` exigem a versão de
  agora (de rename, a da origem).

## Diretórios e renomear

Os diretórios são **explícitos**: `fs.mkdir` cria um, num pai que existe;
`fs.rmdir` remove um vazio. Nada cria o pai de passagem — e por isso nada
passa a existir num caminho que o gate não decidiu.

`fs.rename` move um arquivo ou um diretório inteiro. O gate decide os
**dois** caminhos com `fs.write`: não se move nada para fora do alcance, nem
se traz de fora para dentro. O destino que existe, o pai do destino que
falta e o destino abaixo da origem são recusados. Mover um diretório leva
tudo abaixo, e **cada nó movido recebe versão nova**: quem guardou a versão
de `a/x` não acha nada lá, e não escreve em `b/x` achando que é o mesmo.
Dois renames ao mesmo tempo são serializados pela ordem das gravações: cada
um vê o outro inteiro.

Os caminhos vão na forma normal da política (`politica::caminho`) antes de
qualquer decisão: `..`, `.`, barras repetidas e componentes fora de
`[A-Za-z0-9._-]` são recusados, e `/armazem/compartilhadox` não está abaixo
de `/armazem/compartilhado`. Até 8 níveis, componentes de 1 a 64 bytes.

## Conteúdo binário

O conteúdo de uma gravação vem de **exatamente um** de:

- `content`: texto, no JSON;
- o **anexo** do pedido: bytes quaisquer, fora do JSON, até 60 KiB —
  - de um processo, pela chamada `PEDIR_COM_ANEXO` (a linha e o anexo em
    dois ponteiros);
  - de um agente, em quadros cifrados da sessão cujo texto claro começa com
    o byte zero, antes da linha do pedido, que os declara em
    `"attachment": N`. O anexo é do pedido seguinte e só dele: um tamanho
    que não confere, um anexo que o pedido não declara ou acima do teto é
    recusado antes do gate, e nunca sobra para o pedido depois;
- `draft`: um **rascunho**, para o que passa de um anexo. `fs.draft`
  acrescenta o anexo (ou `content`) a um rascunho de um caminho — os blocos
  vão para o volume na hora, e contam na cota de quem escreve —, e
  `fs.write` com `draft` grava o rascunho inteiro, num lote só. Um rascunho
  é de um dono e de um caminho (o que o gate decidiu ao criá-lo), há no
  máximo 16 no sistema e 4 por dono, e some com os blocos depois de 5
  minutos sem uso. `fs.discard` o descarta antes.

O tamanho de um arquivo não tem teto próprio: o que limita é a cota do
dono e o lugar no volume.

## Cotas

Cada nó tem um **dono** — quem o gravou por último, ou criou o diretório —
e conta para ele: um objeto, e os bytes do conteúdo. O dono é a identidade:
`pessoa:<id>` para uma pessoa (pela sessão dela, ou por um processo que ela
lançou), `agente:<chave>` para um agente, `sistema`, `serial`. Pessoa e
agente passam pelo mesmo mecanismo.

A cota vem da política, por papel, numa linha explícita:

```text
armazem <papel> <bytes> <objetos>
```

e vale **por dono**: duas pessoas operadoras têm cada uma a cota do
operador. Um papel sem linha não tem cota — não grava nada. Um lote que
aumentaria o uso do dono além da cota é recusado inteiro (`DENY_QUOTA`); um
que o diminui passa sempre. Os rascunhos contam junto. A conta é feita com
o lote inteiro sobre o estado de agora, com a ordem das gravações na mão:
dois lotes nunca se conferem ao mesmo tempo, e por isso dois pedidos
concorrentes não somam acima da cota.

Os metadados — caminhos, donos, extensões — moram no heap do kernel, e
têm um teto do armazém inteiro: um oitavo do heap. O conteúdo não conta:
está no volume.

## Arrendamento

Opcional, e exclusivo quando tomado: `fs.claim` toma o objeto por um prazo
(1 s a 5 min, renovado pela atividade do titular), `fs.release` o solta. O
caminho pode ainda não ter nó. Enquanto vale, só o titular muda o objeto —
a versão continua sendo exigida dele também. Sem preempção: ninguém toma o
arrendamento de outro por ter um papel maior, nem o sistema. Ele acaba pelo
titular, pelo prazo, pelo fim da sessão ou da identidade do titular, ou por
`lease.revoke` com a prova de um administrador. A autoridade local
(`sistema`) não tem titular: não arrenda, e só muda um objeto livre.

## Leitura

Pelo VFS: o armazém é mais um sistema de arquivos montado, e `fs.read`,
`fs.list` e o `abrir` dos processos o alcançam pelo mesmo gate (`fs.read`
com o alcance). O conteúdo vem do volume bloco a bloco, sem passar inteiro
pela memória. `fs.stat` diz o tipo, a versão, o tamanho, o dono, o
arrendamento, o uso e a cota de quem pede, e a ocupação do volume.

`fs.read` diz como o conteúdo vem, em `encoding`: `utf-8` quando o
arquivo **inteiro** é texto, `base64` quando não. O que o agente grava pelo
anexo, ele lê de volta. Num texto, o corte de `max` recua até o fim de um
caractere — `returned` diz quantos bytes vieram, e a parte seguinte começa
em `offset + returned` —, e um `offset` no meio de um caractere é recusado.

O nó de um arquivo, para o VFS, é a **versão** dele. Um descritor aberto
antes de uma mudança não lê o conteúdo novo pelo nó velho, nem metade de
cada um: recebe `Erro::Mudou` (no processo, `MUDOU`), e abrir de novo dá o
de agora.

Um bloco de uma versão que ainda vale e não abre é um conteúdo que se
perdeu — outro conteúdo no lugar, ou o disco estragado —, e a leitura
devolve `DoDispositivo` (no processo, `ler -2`), nunca os bytes de outro
arquivo. O log diz a versão, o bloco, o bloco lógico, o motivo, se o que
veio é zero, se uma segunda leitura abre, o que o mapa diz do bloco e os
outros nós que apontam para ele — nada do conteúdo. Na suíte, o armazém
confere ainda, depois de cada operação, que nenhum bloco de um nó ou de um
rascunho está livre no mapa, e, a cada reserva, que ela não deu um bloco
que vale; o disco guarda o rastro das últimas escritas confirmadas, com um
resumo de cada uma, e o bloco que não abre diz quem escreveu nos setores
dele. O penúltimo caso da suíte, `armazem: nenhum bloco que vale se perdeu
na suite`, reprova se qualquer um desses aconteceu — um auxiliar que lê um
arquivo e segue não deixa a perda passar só para o log.

## A cópia de segurança e a restauração

`fs.backup` tira uma fotografia de uma subárvore do armazém — ou dele
inteiro —, e `fs.restore` a põe de volta. São as únicas formas de levar os
dados para fora da máquina e trazê-los de volta inteiros; o código é
`kernel/src/copia.rs`, e o formato, `armazem/src/copia.rs`.

**O que vai na cópia.** Só os dados do armazém: os diretórios, os
arquivos e o conteúdo, como estavam num instante. Nada do estado de
autoridade — pessoas, credenciais, política, lápides, chaves de
assinatura, mensagens, auditoria, a atualização A/B —, que mora no journal
de estado, e que a âncora do TPM existe para nunca voltar atrás; nem a
identidade do Duke, nem segredo nenhum. Restaurar uma cópia de antes de
uma revogação não desrevoga nada: a revogação não está nela.

**O formato.** Um setor em claro — a magia `DUKECOP1`, o formato e a
pública do Duke, só para a recusa dizer por quê — e uma **base** do
`diario`: partes e fecho, cifradas, autenticadas e encadeadas como os
registros do journal. A primeira entrada é o cabeçalho: a pública, a
instalação (o identificador que o journal de estado sorteou ao nascer), a
raiz da cópia, a versão da captura, a geração e o tempo. Depois, os nós em
ordem estrita de caminho — a raiz da cópia primeiro, cada pai antes dos
filhos —, cada arquivo seguido dos pedaços dele (até 60 KiB cada), e o
fecho com os totais. As mesmas regras na escrita e na leitura: uma cópia
que o escritor deixa sair é uma que o leitor aceita, e nenhuma outra.

**A chave.** Derivada da chave do Duke por um rótulo próprio
(`HKDF(sal "Duke copia v1", chave do Duke, "copia: registros")`), como as
do journal e as do volume: calculada quando é usada, zerada depois, nunca
guardada, nunca exportada. Só a identidade que fez a cópia a abre — e só
na instalação dela: outra máquina (outra identidade) recusa com `a copia e
de outra maquina`; a mesma imagem de desenvolvimento noutra máquina, ou
esta mesma depois de reinstalada (outro journal), recusa com `a copia e de
outra instalacao`. O setor em claro só diz por quê: quem o reescreve com a
pública de outra máquina não muda nada, porque a outra máquina não tem a
chave — a recusa passa a ser `a copia nao abre nesta maquina`. A cópia não
leva a identidade: não clona a máquina, não migra nada, não cria
autoridade.

**A cópia** (`fs.backup {"path"}`) é uma leitura: o gate decide `fs.read`
no caminho, com o alcance de sempre — ela não revela nada que a leitura
não revele, e sai cifrada. Com a ordem das gravações na mão do começo ao
fim, a fotografia é de um instante: nenhum lote entra no meio, e nenhum
bloco lido é solto. A cópia fica num **rascunho** de quem pede — no volume,
na cota dele, com o prazo e os tetos dos rascunhos —, e sai em pedaços de
até 48 KiB (`fs.backup {"path","copy","offset","max"}`, em base64). Um
rascunho de cópia não se grava como arquivo, não recebe mais bytes e não
se restaura sem ter sido enviado. A auditoria registra a execução: `feita a
copia <id>`, com a decisão — o `id` é o elo do fecho, que nomeia
exatamente aquela cópia.

**A restauração** (`fs.restore {"path","draft","expect_version"}`) tem a
permissão própria, `fs.restore`, de caminho: trocar uma subárvore inteira
é destrutivo de outro tamanho que uma escrita. A cópia chega por
`fs.draft`, num rascunho do **mesmo caminho** de onde ela veio — a raiz
também: `/armazem` aceita um rascunho só para isso —, e, com a ordem das
gravações na mão:

1. a persistência e o volume de pé, nenhum reinício ou desligamento a
   caminho (`CONFLICT`), a autoridade de quem pediu decidida de novo, os
   arrendamentos de outro titular em qualquer caminho abaixo (`CONFLICT`
   `lease`), e a versão esperada do caminho (`CONFLICT` `version`);
2. a cópia lida e conferida **inteira** — a magia, o formato, a pública, a
   instalação, cada registro no lugar dele, as regras, o fecho, nada
   depois —, com o conteúdo de cada arquivo indo para blocos livres, que
   nenhum metadado aponta. Qualquer recusa (`INVALID_ARGUMENT`, com o
   motivo) solta esses blocos, e nada mudou;
3. o lote: a subárvore de agora sai — do mais fundo para cima — e a da
   cópia entra, cada pai antes dos filhos, preparado pelo armazém como
   qualquer lote: versões novas (nunca uma já vista), **o dono é quem
   restaura** (como numa escrita), a cota dele e o teto dos metadados;
4. a auditoria registra a execução, `restaurada a copia <id>`, com a
   decisão;
5. o armazém resultante vai ao volume como uma **base** na outra região
   do journal dos metadados — o mesmo mecanismo da compactação —, e o
   journal de estado a confirma com `ARMAZEM_CONFIRMADO` e a auditoria,
   num registro só: **o ponto de commit**. Antes dele, nada mudou; depois,
   tudo. Uma queda no meio deixa um ou outro — a bancada corta a energia
   em cada fronteira (`cargo xtask copia`) —, nunca uma mistura;
6. só então o lote vale em memória, os blocos do que saiu voltam a ser
   livres, e o rascunho da cópia some.

Os pedaços enviados contam na cota de quem envia, como qualquer
rascunho; durante a restauração o volume guarda ao mesmo tempo a árvore
de antes, a cópia enviada e o conteúdo novo, até o commit.

## A política padrão

A capacidade é concedida **explicitamente**, por linhas da política — nunca
por código:

```text
papel sistema … fs.write fs.restore …
recurso sistema fs.write /armazem
recurso sistema fs.restore /armazem
armazem sistema 268435456 65536
papel operador … fs.write fs.restore …
recurso operador fs.read … /armazem/compartilhado
recurso operador fs.write /armazem/compartilhado
recurso operador fs.restore /armazem/compartilhado
armazem operador 16777216 4096
papel administrador … fs.write fs.restore …
recurso administrador fs.write /armazem/compartilhado
recurso administrador fs.restore /armazem/compartilhado
armazem administrador 67108864 16384
```

O observador não escreve, não lê, não copia nem restaura. Um programa só
escreve se o manifesto dele declara `fs.write`, e só restaura se declara
`fs.restore`. Tirar `fs.restore` de um papel deixa ele escrever arquivo a
arquivo, sem poder trocar uma subárvore inteira por uma cópia.

- **O administrador.** O papel `administrador` — e o de qualquer credencial
  administrativa — é um **teto**: o que um administrador pode delegar
  (`Politica::cabe_em`). Por isso tem o alcance de `/armazem/compartilhado`:
  para poder atribuir o operador. Teto não é posse: nenhuma sessão exerce
  um papel de teto (`DENY_ROLE`), nenhum papel de teto é atribuível a
  pessoa ou agente, e nem a serial nem a autoridade local podem tê-lo — a
  política que o dissesse é recusada no boot e no `xtask`. A cadeia é teto
  → permissões possíveis → política → gate → operação, e o teto só entra
  no primeiro elo.
- **A emergência.** O `sistema` da política de emergência é o **mesmo
  texto** do da padrão, e a linha de `fs.write` e a cota dele vêm junto,
  escritas. Não há `ALLOW(*)`, curinga ou exceção de código.

## O que não está aqui

- Restaurar num volume recusado, depois de perder o disco (e com ele o
  selo da identidade), noutra máquina, ou o estado de autoridade: cada um
  pede uma decisão nova — ver o grupo B em `docs/OPERACAO.md`. Hoje a
  arquitetura recusa os quatro: o volume recusado não grava, a cópia de
  outra identidade ou instalação não abre, e o estado de autoridade não
  está na cópia.

- Links, permissões por arquivo e listas de acesso: o alcance é o da
  política, por prefixo de caminho.
- Desfragmentação: o mapa procura uma faixa contígua e, se não há, até 64
  faixas por escrita; um volume muito fragmentado recusa (`ERROR`) uma
  escrita que precisaria de mais. No pior caso — blocos livres alternados —
  uma escrita ainda leva 64 blocos (≈ 255 KiB). A recusa é limpa: nada é
  escrito, a cota e o mapa ficam como estavam, e o volume segue; mover
  blocos com o volume vivo pediria um registro de mudança com queda no
  meio, sem nenhuma propriedade de segurança, consistência ou recuperação
  a ganhar.
