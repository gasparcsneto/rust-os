# A atualização A/B

Como o Duke troca o código que decide — o kernel e os programas — sem
perder a máquina: dois slots, um manifesto assinado, a instalação por
quórum, a tentativa contada pelo iniciador, a confirmação no journal e a
volta sozinha quando a versão nova não presta. É o B1 do relatório de
prontidão (a decisão 15.1: "A/B + assinatura criptográfica + anti-rollback
protegido pelo TPM").

O código: o crate [`atualizacao/`](../atualizacao) (os formatos e as regras,
testados no hospedeiro, com uma simulação de quedas de energia),
[`iniciador/src/slots.rs`](../iniciador/src/slots.rs) (o lado do firmware),
[`kernel/src/slots.rs`](../kernel/src/slots.rs) (o lado do kernel) e, no
`xtask`, [`slots.rs`](../xtask/src/slots.rs),
[`producao.rs`](../xtask/src/producao.rs) (publicar, provisionar, operar) e
[`atualizar.rs`](../xtask/src/atualizar.rs) (a bancada).

## O que não muda

A atualização não é uma segunda arquitetura de segurança. Ela passa pela
mesma cadeia de toda operação de autoridade —
identidade → autoridade → política → gate → recurso → auditoria →
proveniência → persistência:

- **Identidade**: nenhuma nova. A chave de atualização não é uma
  credencial: não entra por porta nenhuma, não prova operação nenhuma, não
  instala nada. Ela só diz quem publicou uma imagem — como a chave de um
  editor diz quem selou um código.
- **Autoridade**: a operação de quórum `system.update`, pelo mecanismo de
  quórum que já existia (`admin.revoke`): M credenciais administrativas do
  grupo da imagem assinam o mesmo pedido, sobre o mesmo desafio, a mesma
  versão da política e a mesma geração administrativa. Nenhuma credencial
  sozinha instala, e `system`/`root` não ganham `ALLOW(*)`.
- **Política**: a permissão `system.update`, enumerada como qualquer outra
  — sensível e não administrativa, como `system.power`. O papel `sistema`
  a exerce pelo gate para **escrever** a versão nova no slot inativo
  (`update.stage`); o papel de **cada** credencial que assina a instalação
  precisa tê-la; e a linha `quorum system.update M N` da política diz o M e
  o N, com o mesmo piso da revogação (M ≥ 2 e M/N ≥ 2/3). Sem a linha, a
  operação não existe.
- **Gate**: `update.stage` e `update.status` são comandos do agente como
  os outros, decididos pelo gate central, auditados, com a taxa do papel.
- **Persistência**: o estado da atualização mora no journal, ancorado no
  contador do TPM — o mesmo de ICP-5. Nenhum índice de NV novo, nenhuma
  custódia nova.
- **Auditoria**: a cadeia de sempre. Cada passo — a escrita, as
  assinaturas, a instalação, a tentativa, a confirmação, o desfazimento, a
  recusa, a regravação do controle — é um registro dela, no mesmo registro
  do journal que muda o estado quando muda.

## O disco

As partições de antes não mudam de lugar; três entram depois delas:

| partição | setores | o que guarda |
|---|---|---|
| ESP (FAT32) | 2048.. | só o iniciador, `\EFI\BOOT\BOOT{X64,AA64}.EFI` |
| raiz (Btrfs) | 100352.. | a máquina: `/etc/duke` — os registros, a política, a rede, o registro de atualização |
| estado | 428032.. | o journal (ICP-5) e, na reserva do fim, o selo da identidade do Duke (B2) |
| armazém | 460800.. | o volume do armazém |
| controle | 591872.., 1 MiB | as duas cópias do controle de boot |
| slot A | 593920.., 48 MiB | uma imagem: cabeçalho, kernel, pacote |
| slot B | 692224.., 48 MiB | a outra |

O código fica nos slots; o estado, fora deles. Uma versão nova troca o slot
inteiro e não toca a raiz, o journal nem o armazém: a identidade, as
credenciais, a política, as chaves seladas, o estado administrativo, os
arquivos, a auditoria e a proveniência continuam onde estavam. A
identidade de uma máquina de produção nasce no primeiro boot, selada no
TPM, e o selo mora na partição de estado — não num slot —, sem depender
da medição do boot: a versão nova na tentativa, a confirmada e a velha de
volta abrem a mesma (ver "A identidade do Duke" em
[`OPERACAO.md`](OPERACAO.md)). A bancada confere as duas: a versão nova
de uma imagem de produção se confirma com a identidade nascida na velha,
e a que entra em pânico na tentativa volta para a velha com ela.

## A imagem de um slot

```text
      0  cabeçalho, 4 KiB: "DUKESLT1", versão, tamanho do manifesto,
         a assinatura Ed25519 (64), a chave pública que assinou (32), o
         manifesto
   4096  o kernel ELF, sem as seções de depuração
      …  o pacote, alinhado a 4 KiB
```

O **manifesto** é texto canônico — uma grafia só, conferida pelo leitor:

```text
formato 1
arquitetura x86_64
versao 2026.10.1
geracao 7
estado 1 1
kernel 4728328 <blake2s>
pacote 3100000 <blake2s>
```

- `geracao` é o número do anti-rollback: uma versão nova tem de ter
  geração **maior** que a ativa;
- `estado` são os formatos do estado persistente que a imagem lê e grava;
  a máquina recusa uma imagem que não lê o formato de agora;
- a assinatura é Ed25519 estrita (`verify_strict`) sobre um rótulo próprio
  seguido do BLAKE2s-256 do manifesto — uma assinatura de manifesto não
  vale como selo de código nem como quórum;
- o **resumo do manifesto** (BLAKE2s-256 dos bytes dele) nomeia a imagem:
  é o que o quórum assina, o que o journal guarda e o que o controle diz.

O **pacote** é um índice simples de arquivos só de leitura (`DUKEPAC1`): os
programas do produto e os dados públicos — as âncoras TLS, a rede
principal do IC. Cada diretório do topo é montado em `/<nome>`, por cima da
raiz, como código da imagem. Nada em `etc/`: a configuração e a identidade
da máquina não vêm numa atualização.

## Quem confia em quê

- **Quem publica** tem a chave privada de atualização (`cargo xtask chave
  atualizacao`), fora da máquina, e assina o manifesto (`cargo xtask
  publicar`).
- **A máquina** tem o registro das chaves públicas em que confia,
  `/etc/duke/atualizacao` — na raiz, do provisionamento, no formato do
  registro de editores. Uma atualização não o troca (o pacote não tem
  `etc/`).
- **O kernel** confere a imagem inteira duas vezes: na instalação — o
  cabeçalho, a assinatura com uma chave do registro, a arquitetura, o
  formato do estado, o tamanho no slot, o kernel e o pacote pelos resumos,
  e a geração acima do piso — e no boot dela, antes de lhe dar autoridade.
- **O iniciador** não lê a raiz nem confere assinatura: confere resumos — o
  do manifesto do slot contra o que o controle guarda para ele, e o do
  kernel contra o do manifesto — e a forma do ELF. O resumo no controle é a
  marca da conferência que o kernel fez ao armar o slot.
- **O controle de boot** não decide nada: é o aviso de que o iniciador
  precisa para bootar sem ler o journal. O kernel o confere contra o journal
  a cada boot e o regrava quando discordam. Quem tem o disco na mão forja um
  controle à vontade — e o kernel que boota dele se recusa, se não é a
  ativa nem a candidata do journal.

## O anti-rollback

O **piso** é a geração da imagem ativa, e mora no journal. O journal é
ancorado no contador NV do TPM (ICP-5): cada registro de estado avança o
contador, e um journal que fica atrás do contador — um disco devolvido a
uma cópia antiga — é recusado. Por isso o piso não volta atrás: voltar o
piso é voltar o journal, e voltar o journal é o que a âncora recusa.

A decisão 15.1 falava em "a versão mínima num índice do TPM" e em
"anti-rollback como o da âncora do journal". As duas leituras dão o mesmo
efeito; esta implementação fica com a segunda, que é a arquitetura já
estabelecida no ICP-5, e não cria um segundo mecanismo de custódia:

- a confirmação — a troca da ativa e o piso novo — entra num **único**
  registro do journal, que avança o contador **uma** vez. Não há uma janela
  em que o TPM diga uma versão mínima e o journal outra, como haveria com
  um índice de NV à parte, escrito antes ou depois do journal;
- o índice de NV de uma versão mínima seria um segundo contador a manter
  coerente com o primeiro, com as suas próprias quedas de energia — e o
  pedido do B1 é não inventar um segundo mecanismo de custódia;
- sem TPM — ou diante de outro, ou de um TPM limpo —, a persistência é
  recusada como em ICP-5, e com ela a autoridade: nenhuma versão se
  confirma, e nenhuma operação de autoridade passa.

Nenhuma imagem abaixo do piso ganha autoridade: o kernel que boota dela se
recusa, regrava o controle pelo journal e reinicia para a ativa.

## O fluxo inteiro

1. **Publicar** (fora da máquina): `cargo xtask publicar <chave> <versão>
   <geração>` monta a imagem — o kernel de produção, o pacote do produto, o
   manifesto — e a assina. A saída diz o resumo do manifesto.
2. **Escrever** (`update.stage`, pelo gate, papel com `system.update`): os
   bytes vão para o **slot inativo**, em pedaços, a partir de um
   deslocamento. Nada no journal: escrever não é instalar. Antes de o slot
   mudar, o controle passa a dizer o journal — o inativo, sem manifesto no
   controle, não boota no meio da escrita. Recusado com uma versão armada.
3. **Instalar** (o quórum `system.update`, `{"action":"install",
   "manifest":<resumo>}`): o kernel confere o slot inativo inteiro de novo
   — com a vez no slot presa: nenhuma escrita o muda até a operação acabar
   —, e a geração acima do piso. A candidata entra no journal no registro
   da operação (que avança o contador e a geração administrativa); depois,
   o controle passa a dizer a tentativa: o slot dela, o manifesto, e
   `TENTATIVAS` (3) tentativas.
4. **Desistir**, se se quer (`{"action":"cancel"}`, o mesmo quórum): a
   candidata sai do journal, e o controle volta a dizer só a ativa.
5. **Reiniciar** (`system.reboot`). O iniciador lê o controle, desce a conta
   de tentativas — gravada e descarregada **antes** de bootar —, confere a
   imagem nova e a entrega ao kernel no modo `tentativa`.
6. **Tentar**: o kernel novo confere a si mesmo (a assinatura com o
   registro da máquina, a arquitetura, o formato do estado, o pacote), abre
   a persistência e reconcilia com o journal: é a candidata, numa
   tentativa. Até a confirmação, ele não tem autoridade; um pânico ou uma
   falha fatal reiniciam a máquina em vez de parar.
7. **Confirmar**, no fim do boot — depois dos núcleos e antes dos programas
   e dos canais: a candidata vira a ativa e o piso sobe para a geração
   dela, num registro do journal. **É o ponto de irreversibilidade**: dali
   em diante a versão velha está abaixo do piso e não boota com
   autoridade. O controle passa a dizer a nova, com o manifesto da velha
   zerado. A autoridade volta.
8. **Voltar**, se a nova não presta: a carga recusada pelo iniciador, a
   imagem que recusa a si mesma, o pânico, a máquina que trava (e alguém a
   desliga), a energia que cai — cada boot de tentativa gasta uma. Sem
   tentativas, o iniciador boota a ativa no modo `desfeita`, e o kernel dela
   tira a candidata do journal com o motivo, e regrava o controle.

## O estado e a reconciliação

O journal guarda duas coisas: a **ativa** (slot, manifesto, versão,
geração) e, se há, a **candidata**. O piso é a geração da ativa. As
transições: linha de base (o primeiro boot de um slot numa máquina sem
estado), armar, cancelar (pelo quórum), confirmar e desfazer (pelo kernel,
no boot). A instalação e a desistência entram no registro da operação de
quórum; a linha de base, a confirmação e o desfazimento, num registro
próprio (`ATUALIZACAO`), que avança o contador e não a geração
administrativa. A base da compactação leva o estado.

A cada boot, com a persistência aberta e antes de qualquer serviço, o
kernel confere o que o iniciador contou — o slot, o modo, o resumo do
manifesto — contra a imagem que ele mesmo conferiu, o journal e o controle,
e decide (`atualizacao::estado::reconciliar`):

| o boot | o journal | a decisão |
|---|---|---|
| fora de um slot | com estado | recusa a autoridade |
| a imagem não confere | — | numa tentativa: acaba a tentativa (falha no controle) e reinicia; fora dela: o controle volta a dizer o journal e reinicia — ou, se é a própria ativa, recusa e para |
| tentativa | sem persistência, ou sem estado | acaba a tentativa e reinicia |
| — | sem estado | linha de base |
| a candidata, numa tentativa | — | confirma no fim do boot |
| a candidata, fora de tentativa | — | recusa; o controle volta a dizer o journal |
| a ativa, desfeita ou com as tentativas a zero | candidata armada | desfaz |
| a ativa | — | segue; o controle volta a dizer o journal, se discorda |
| outra imagem — abaixo do piso, ou nem ativa nem candidata | — | recusa a autoridade; o controle volta a dizer o journal e reinicia |

Um boot recusado não decide nada: toda operação de autoridade é recusada
com o motivo (`slots::exigir`, que a persistência consulta), e o que só lê —
`update.status`, os registros, a auditoria — continua respondendo.

## As migrações

O B1 não migra nada: o formato do estado persistente — o journal e o
armazém — é o 1 (`FORMATO_DO_ESTADO`), e o código mora nos slots, longe
dele. A regra para quando um formato mudar já vale: o manifesto diz os
formatos que a imagem lê (`estado <menor> <maior>`), e a instalação e o
boot recusam uma imagem que não lê o formato de agora — a bancada tenta uma
de formato 2. Uma migração entra como uma imagem que lê o formato velho e o
novo, e só passa a gravar o novo depois da confirmação, o ponto sem volta:
antes dele, a velha, numa volta, ainda lê tudo o que a nova deixou.

## Quedas de energia, passo a passo

O journal decide primeiro; o controle segue. Em cada fronteira:

- **na escrita da versão nova**: o slot inativo fica pela metade; o
  controle não tem manifesto para ele, o iniciador não o boota, e a
  instalação da metade é recusada pelos resumos. Escrever de novo resolve;
- **na instalação**, antes do registro: nada armado. Com o registro no
  disco — escrito, descarregado, o contador avançado ou não —: armada; o
  boot seguinte, da ativa, vê o journal armado e o controle não, e regrava
  o controle. Depois do controle: armada, inteira;
- **no boot da tentativa**: o iniciador gravou a conta antes de bootar; o
  boot seguinte tenta de novo, enquanto houver tentativas, e depois volta;
- **na confirmação**, antes do registro: a tentativa continua contando; com
  o registro: a nova é a ativa, e se o iniciador voltar para a velha, ela se
  recusa abaixo do piso e regrava o controle para a nova;
- **no desfazimento**: sem o registro, a velha desfaz de novo no boot
  seguinte; com ele, segue;
- **numa gravação do controle**: as duas cópias — a escrita vai sempre na
  que não vale, com a sequência seguinte; um rasgo estraga só ela. As duas
  estragadas: o iniciador sintetiza um controle pelos cabeçalhos dos slots
  e alterna entre eles, e o kernel o regrava pelo journal.

A simulação do crate (`atualizacao/tests/simulacao.rs`) corta a energia em
cada escrita de cada sequência — o journal, as duas cópias do controle, o
slot — e confere, depois de cada corte, que a máquina tem um slot bootável
com autoridade, que o piso não desce e que a versão abaixo dele não ganha
autoridade. A bancada (`cargo xtask atualizacao`) corta de verdade, no
emulador, em cada fronteira acima.

## Concorrência

- O slot inativo tem uma **vez**: a escrita e a instalação a tomam antes de
  ler o estado, e quem chega na vez de outro é recusado (`CONFLICT`). Uma
  instalação que armasse no meio de uma escrita não é possível: a escrita
  que tem a vez já leu o estado com a armada, e se recusa.
- Duas instalações ao mesmo tempo: uma arma; a outra é recusada pela vez,
  pela geração administrativa que mudou desde o desafio dela, ou pela
  candidata que já existe.
- A instalação, a desistência, o reinício e o desligamento passam pela ordem
  das gravações da persistência: um de cada vez. Com um reinício a caminho,
  nada da atualização começa.
- A confirmação acontece uma vez por boot, pelo kernel, no fim dele.

## O que o operador faz

```sh
# Uma vez: a chave de atualização, e a linha dela no diretório do operador
cargo xtask chave atualizacao ~/chaves/publicador-1 publicador-1 >> op/atualizacao

# Cada versão: a imagem, assinada
cargo xtask publicar ~/chaves/publicador-1 2026.11.0 2 --release

# Uma máquina nova: o disco, com a imagem no slot A
cargo xtask provisionar op --imagem target/atualizacao/2026.11.0-x86_64.slot

# Uma máquina que já roda: escrever, instalar pelo quórum, reiniciar. O
# duke.publica é a pública que a máquina mostrou no console no primeiro boot.
cargo xtask operar maquina:7070 update.stage --imagem target/atualizacao/2026.12.0-x86_64.slot \
    --chave sistema-1 --duke duke.publica
cargo xtask operar maquina:7070 system.update '{"action":"install","manifest":"<resumo>"}' \
    --chave sistema-1 --duke duke.publica --assinatura adm-a --assinatura adm-b
cargo xtask operar maquina:7070 system.reboot --chave sistema-1 --duke duke.publica
cargo xtask operar maquina:7070 update.status --chave sistema-1 --duke duke.publica
```

O `update.status` diz o boot (o slot, o modo, a imagem conferida, a
versão, a geração, quem a assinou), a reconciliação, a autoridade, o
journal (o piso, a ativa, a candidata) e o controle (a cópia que vale, a
sequência, o bom, a tentativa, as restantes, a falha).

## A auditoria

| método | quando | recurso | detalhe |
|---|---|---|---|
| `update.stage` | cada pedaço escrito, ou recusado | o slot | os bytes e o intervalo, ou o motivo |
| `system.update` | cada assinatura conferida, e o desfecho do quórum | o manifesto | quem assinou, o desafio, a versão da política; instalar ou cancelar, a imagem, quem a publicou, de que slot |
| `system.update.baseline` | a linha de base | o manifesto | a imagem |
| `system.update.attempt` | a tentativa conferida | o manifesto | a imagem |
| `system.update.confirm` | a confirmação | o manifesto | a imagem |
| `system.update.rollback` | o desfazimento | o manifesto da desfeita | o motivo: a carga recusada, a recusa de si mesma, as tentativas que acabaram |
| `system.update.refuse` | um boot recusado | o manifesto do boot | o motivo, o slot e o modo |
| `system.update.control` | o controle regravado pelo journal | o manifesto do boot | o modo |

Os registros do kernel entram no journal no mesmo registro da transição.
A recusa de um boot, que não muda o estado, vai ao journal num registro só
de auditoria antes do reinício: gravar a auditoria pede o journal de pé, e
não a autoridade que o boot recusado acabou de perder.

## Os testes

- `cargo test -p atualizacao`: os formatos, as transições, a reconciliação
  e a simulação de quedas — cada corte de energia em cada escrita, e 3000
  rodadas aleatórias de operações, cortes, reinícios e controles estragados.
- A suíte do kernel (os casos `atualizacao:`): o `update.status`; o
  `update.stage` pelo gate, só para o papel com `system.update`; o quórum
  pelo M da política e pela permissão no papel de cada assinante; a
  compactação levando o estado; a escrita conferindo o pedaço e o slot, e
  nada começando com um reinício a caminho; e o boot recusado gravando o
  porquê no journal antes de reiniciar, sem decidir nada.
- `cargo xtask atualizacao` — a bancada, nas duas arquiteturas, pelo
  firmware (OVMF, AAVMF): a atualização inteira com o estado da máquina
  preservado; a versão velha forjada no controle e reescrita no slot; a
  carga recusada; as recusas da instalação; a desistência; as duas cópias do
  controle estragadas; sem TPM e com outro TPM; o disco que falha no slot
  inativo (o erro de mídia do disco hostil na escrita, na instalação e na
  carga); a concorrência; o caminho do operador numa imagem de produção; o
  kernel fora de um slot (ARM); e, com os pontos de queda, cada fronteira
  da instalação, da confirmação, da escrita e do desfazimento, e o pânico
  em toda tentativa. Na CI, um job por arquitetura: a bancada inteira levou
  65 minutos no x86 e 53 no ARM.
- `cargo test -p xtask`: a chave de atualização, o registro do operador, a
  imagem conferida pelo registro.

### As mutações

Cada proteção da atualização foi tirada ou enfraquecida, uma de cada vez, e
o detector mais barato que a deve pegar rodou contra ela: os testes do
hospedeiro do crate, os casos `atualizacao:` da suíte, ou cenários da
bancada (x86). A rodada de controle, sem mutação, passou em todos — o
hospedeiro, a suíte (678 de 678) e os quatro cenários dela. As dezoito
foram reprovadas:

| | a mutação | quem reprovou |
|---|---|---|
| M01 | o manifesto sem assinatura que confira é aceito | 2 testes do hospedeiro |
| M02 | o kernel não confere a assinatura do manifesto | a bancada: as recusas da instalação |
| M03 | a candidata não precisa de geração acima do piso | 3 testes do hospedeiro; as recusas |
| M04 | a imagem abaixo do piso ganha autoridade | 6 testes do hospedeiro; a versão velha que não volta |
| M05 | a confirmação grava o controle antes do journal | as quedas na confirmação |
| M06 | a confirmação vale para a candidata com outra imagem no boot | 8 testes do hospedeiro |
| M07 | o desfazimento é ignorado | 6 testes do hospedeiro; a carga recusada |
| M08 | a tentativa sem o journal continua | 3 testes do hospedeiro; sem o TPM |
| M09 | o `update.stage` pela permissão de leitura | a suíte: o `update.stage` pelo gate |
| M10 | a escrita responde e não escreve | a atualização inteira |
| M11 | a decisão do boot sem auditoria | o primeiro boot |
| M12 | o quórum sem a permissão no papel de quem assina | a suíte: o quórum pela política |
| M13 | o quórum com menos que o M da política | a suíte: o quórum; as recusas |
| M14 | a escrita por cima da versão armada | as recusas |
| M15 | o iniciador não confere o resumo do kernel | a carga recusada |
| M16 | o iniciador não desce a conta antes da tentativa | 5 testes do hospedeiro; o pânico na tentativa |
| M17 | a imagem de uma chave fora do registro boota e instala | as recusas |
| M18 | a recusa do boot reinicia sem gravar o porquê | a suíte: o boot recusado; a versão cancelada |

A M18 é o defeito que a bancada achou de verdade: o B1 tinha posto a
autoridade do boot na `persistencia::exigir`, e a gravação da auditoria
passava por ela — um boot recusado reiniciava sem o porquê no journal, a
não ser que o coletor da auditoria chegasse antes. A gravação da auditoria
agora pede só o journal de pé.

No ARM, quatro delas de novo, contra a bancada pelo AAVMF: a assinatura e
a chave que o kernel confere (M02, M17), o resumo do kernel que o
iniciador confere (M15) e o porquê do boot recusado (M18). O controle
passou nos três cenários e no caso do boot recusado da suíte; a M02, a M15
e a M17 foram reprovadas pelos mesmos cenários do x86. A M18 passou pela
versão cancelada no ARM — o coletor chegou ao journal antes do reinício e
levou o porquê, a corrida que o parágrafo acima descreve —, e o caso da
suíte, que pausa o coletor, a reprovou: é ele o detector dela.

### O tamanho

O kernel de produção (release) cresceu 84 904 bytes no x86 (+2,11%) e
88 832 no ARM (+2,61%), pela soma dos segmentos carregáveis — 95 784 e
107 176 bytes no ELF sem as seções de depuração, que é o que vai no slot.
O iniciador foi de 42 496 para 81 920 bytes no x86 e de 34 304 para 67 072
no ARM: o controle, a GPT, o cabeçalho e o manifesto, o BLAKE2s e a forma
do ELF — sem o Ed25519, que ele não usa. Os programas não mudaram, e o teto
de 1 MiB do executável também não.

## O que fica de fora

- **O iniciador não se atualiza**: ele mora na ESP, e uma versão nova dele
  vai por um provisionamento novo da ESP. Ele é pequeno e muda pouco; um
  iniciador A/B pediria um segundo carregador antes dele.
- **Sem Secure Boot**: o firmware não confere o iniciador. Quem tem o disco
  na mão troca o iniciador e o controle — e um kernel de fora de um slot,
  ou abaixo do piso, continua sem autoridade, porque é o journal ancorado no
  TPM que a dá. O Secure Boot é do firmware, fora deste incremento.
- **Sem watchdog**: uma versão nova que trava sem entrar em pânico fica
  travada até alguém desligar a máquina; o boot seguinte gasta uma
  tentativa e, sem elas, volta.
- **A ativa estragada no disco**: o kernel dela não confere, se recusa e
  para (não há outra versão com autoridade para onde ir). A recuperação é
  reescrever a mesma imagem no slot — um provisionamento do slot, ou um
  `update.stage` de outra máquina —, e o journal, intacto, a aceita de
  volta.
- **O primeiro boot**: um kernel fora de um slot, numa máquina sem estado de
  atualização no journal, não tem o que comparar — é a linha de base de uma
  máquina que nunca bootou de um slot.
