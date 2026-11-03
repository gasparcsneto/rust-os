# O pareamento da Pessoa (D8)

Este documento descreve o **D8**, o que está implementado e testado: a
Pessoa relaciona um dispositivo dela — outro Duke — com este Duke **sem o
administrador**, numa cerimônia diante das duas máquinas, e desfaz a
relação dela quando quiser (`device.forget`). É o autosserviço que o
estágio 1 do enlace ([ENLACE.md](ENLACE.md)) deixou para depois: lá, a
relação nasce do `device.register` do administrador; aqui, nasce da
Pessoa, e é **a mesma relação** — o mesmo registro de dispositivos, o
mesmo enlace, o mesmo gate, a mesma auditoria.

O caminho, de ponta a ponta:

```
Pessoa → identidade (a sessão dela, no console, pelo teclado)
  → Policy (device.pair; device.forget sobre dispositivo:<nome>; o papel cabe no dela)
  → Gate (a decisão, gravada)
  → cerimônia (o Noise IK com a chave do Duke, os dois códigos, a senha)
  → reconfirmação do Gate no commit (em ordem, com a persistência)
  → relação persistente (journal, com a decisão)
  → depois: Pessoa ∩ relação ∩ remoto, a cada pedido do outro Duke
```

**Parear não é autorizar.** A relação pareada não dá ao outro Duke nada
além do que a do administrador daria: o conjunto fechado do enlace,
decidido por Pessoa ∩ relação ∩ `remoto`, com o papel da relação contido
no da Pessoa. Nenhum dispositivo vira `ALLOW(*)`; os nomes continuam
enumerados na política (`dispositivo:par`, `dispositivo:par-2`), sem
curinga.

## A decisão (DN-1, opção A)

- o **Noise IK** de sempre, com a chave do Duke (B2) como a única
  identidade criptográfica de cada lado — nenhuma chave, primitiva ou
  identidade nova;
- um **prólogo próprio** (`Duke pareamento entre dispositivos v1`): um
  aperto de cerimônia não abre como enlace nem como agente, e o contrário
  também não;
- o Duke que aceita **anuncia a pública** dele antes do aperto, com um
  **desafio** de 16 bytes que só vale para aquela janela;
- quem inicia **se compromete com um nonce** (`c = H(n)`) antes de ver a
  efêmera do outro, e só o abre depois da segunda mensagem do IK;
- **dois códigos** de 8 dígitos, um para cada direção, derivados do resumo
  do aperto `h` e do nonce: cada Duke mostra o código que a Pessoa digita
  no **outro**;
- a confirmação pede também a **senha** da Pessoa, na janela de tentativas
  do login;
- cada lado só grava com a confirmação dele **e** o `conferido` do outro.

As contas são puras e testadas no hospedeiro
([`politica/src/pareamento.rs`](../politica/src/pareamento.rs)):
`compromisso(n) = BLAKE2s("…compromisso…" ‖ n)`, `codigos(h, n)` — os 40
bits iniciais e os 40 seguintes de `BLAKE2s("…codigo…" ‖ h ‖ n)`, cada um
módulo 10⁸ — e `relacao(h, n)`, os 16 bytes iniciais de
`BLAKE2s("…relacao…" ‖ h ‖ n)`: o identificador da relação é **o mesmo
nos dois lados**, sem que nenhum o escolha.

## Os comandos

No console, pelo teclado — como `login` e `senha`, um agente não os
confirma, e as linhas da cerimônia não se editam pela árvore semântica,
nem para esvaziar: nem no console físico, nem num Terminal, onde a árvore
as mostra como o campo da janela dele e o kernel recusa a ação antes de
ela chegar ao programa (o caso "terminal: o agente nao edita nem confirma a
linha da senha", no [README](../README.md#consoles)):

- `aceitar <nome> <papel> [<endereço>]` — abre a janela (120 s): a 7071
  passa a escutar, e a tela mostra a impressão deste Duke e o endereço;
- `parear <nome> <endereço> <papel>` — o fio da cerimônia, com o papel
  `servico enlace`, conecta ao endereço pelo gate e conduz o protocolo;
- `device.forget {"device":"dispositivo:<nome>"}` — desfaz a relação da
  Pessoa com o dispositivo; só a dela.

`device.registry` mostra a cerimônia em curso — o lado, o passo, o nome, a
impressão do par, o tempo que falta e o console —, e nunca o código, o
nonce, o desafio ou o resumo do aperto.

## O protocolo

```
Pessoa em B: aceitar        Duke B                          Duke A        Pessoa em A: parear
                             ◀──── PedidoDaChave (6, vazio)
                             ChaveDoDuke (7: pública de B ‖ w) ────▶  confere a chave anunciada
                             ◀──── InicioPareamento (8): IK 1ª, carga {"commit": c, "janela": w}
   confere w, a chave que o IK provou; ocupa a janela
                             Resposta (2): IK 2ª ──────────────────▶  transporte; h
                             ◀──── {"nonce": n}
   H(n) == c; códigos e R                                               códigos e R
   mostra K_B; pede o código do outro                                   mostra K_A; pede o código do outro
   digita K_A, e a senha ──▶ {"estado":"conferido"} ◀──── digita K_B, e a senha
   gate de novo, em ordem: grava                                        gate de novo, em ordem: grava
                             {"estado":"gravado","relation":R} (os dois sentidos)
   "pareado: …; o outro gravou"                                         "pareado: …; o outro gravou"
```

Depois do aperto só passam o `nonce` (uma vez), o `conferido` e o
`gravado` (uma vez de cada lado, com o mesmo `R`) e o `desistiu` (com o
motivo); qualquer outra coisa encerra e desfaz. A vaga da 7071 decide
pelo primeiro quadro: uma sessão de cerimônia nunca vira enlace, nem o
contrário. O Duke que aceita responde a **uma** primeira mensagem por
janela, e só se ela traz o desafio desta janela: a primeira mensagem
gravada de outra cerimônia não ocupa nada.

Quem inicia, depois do fim, espera o outro fechar a conexão — no prazo de
um fecho, 5 s — e só então fecha: a vaga do enlace do outro lado larga o
que chega junto com o FIN, e o último `desistiu` ou `gravado` se perderia.

## Os estados

A cerimônia é uma só por Duke, sob uma trava
([`kernel/src/pareamento.rs`](../kernel/src/pareamento.rs)), e a conta
dela é a de `politica::pareamento`:

```
Aberta ─▶ Ocupada ─▶ Apertada ─▶ CodigoCerto ─▶ ConferidaAqui ─▶ Gravando ─▶ Gravada ─▶ Fim(Concluida)
   └─────────────── de qualquer um antes de Gravada: Fim(Desfeita(motivo)) ───────────────┘
```

O código certo pede a senha; o errado — ou fora da forma — acaba com a
cerimônia nos dois lados, sem segunda tentativa. Os prazos: **120 s** para
a janela receber o aperto; **180 s** para a cerimônia inteira, contados da
abertura e conferidos de novo no commit. A gravação acontece na vez do
console da Pessoa — no Enter da senha, ou quando o `conferido` do outro
chega depois —, e uma desistência que chega durante a gravação espera por
ela: o fim sai da gravação, e não da corrida.

Os fins: `Concluida` (os dois gravaram); `Desfeita(motivo)` (nada
gravado); `GravadaSemAviso` (este lado gravou e o outro não confirmou —
a tela diz para conferir nele); `DesfazerAqui` (o outro desistiu depois
de este lado gravar: a relação sai daqui, como num `device.forget`).

## A autoridade

| Quem | Pode | Não pode |
|---|---|---|
| a Pessoa, no console, pelo teclado | abrir (`device.pair`), com um nome do alcance de `device.forget` dela e um papel que cabe no dela; confirmar com o código do outro e a senha; esquecer as **próprias** relações | parear pela árvore semântica, por processo ou pela rede; escolher o id da relação; dar ao dispositivo mais do que ela tem; esquecer a relação de outra Pessoa; pôr lápide |
| um agente | ver (`device.registry`) | parear; confirmar a linha da cerimônia |
| o administrador | `device.register`, `device.revoke`, `device.suspend` (o estágio 1) | — |
| o fio da cerimônia | `net.connect`, `net.send`, `net.recv`, pelo papel `servico enlace` | decidir; gravar; falar pela Pessoa |
| o outro Duke, na cerimônia | provar a chave dele e mandar as mensagens dela | pedir qualquer coisa: a sessão da cerimônia não tem chamador |
| o outro Duke, depois | pedir pelo enlace o conjunto fechado, decidido por Pessoa ∩ relação ∩ `remoto` | `device.pair`, `device.forget`, ou qualquer coisa fora do conjunto |

A decisão é a do gate de sempre, com a Pessoa como titular
(`autorizacao::decidir_pareamento`), na abertura e **de novo no commit**,
dentro da ordem da persistência: a política que mudou, a Pessoa revogada,
a sessão que acabou, a chave revogada ou suspensa, o desligamento a
caminho — tudo o que mudou entre a abertura e o commit recusa a gravação.
O papel da relação tem de caber no da Pessoa (`cabe_em`), e não pode ser
o teto de um administrador. A chave do par não pode ser a deste Duke, nem
a de um agente ou de um administrador, nem ter lápide, nem estar
suspensa — conferido no anúncio, no aperto e no commit.

## A persistência

A relação pareada vai ao journal como a do administrador — o registro de
dispositivos, com a decisão do gate no mesmo registro —, e volta no boot.
`device.forget` grava o registro **44** (`RELACAO_DESFEITA`), também com a
decisão, antes de responder; no boot, ele desfaz a relação de novo, e
**nunca** é lápide: a mesma chave pode parear outra vez, com outro `R`.
Se era a última relação do dispositivo, ele sai do registro; se era a
última do Duke, a 7071 para de escutar.

**A meia relação.** Não há transação distribuída: se um lado grava e o
outro cai antes de gravar, fica uma relação de um lado só. Ela não tem
autoridade a mais — é uma relação como as outras, decidida por Pessoa ∩
relação ∩ `remoto` —, é **visível** no `device.registry`, é **inerte**
(o outro lado não tem relação por onde pedir, e quem aceitou não tem o
endereço de quem iniciou), é **auditável** (a gravação está na auditoria
e no journal) e sai com o `device.forget` da Pessoa.

## Auditoria e proveniência

Pelo modelo de sempre, numa cadeia só: `device.pair` com a Pessoa como
titular — a abertura (`janela aberta; papel …; <console>` ou `para
<endereço>; papel …`), a gravação (`pareado: relacao <R>, par
<impressão>; <console>`, cuja decisão vai no registro do journal) e a
desfeita (`desfeita: <motivo>; par <impressão>`); `pair.open`, sem
titular, com a chave que o aperto provou (ou alegou, na recusa); e
`device.forget`, a decisão e a execução (`relacao <R> desfeita; N
entregas anuladas`). Nenhum registro leva o código, o nonce, o desafio ou
o resumo do aperto, e todos cabem no teto do detalhe (96 bytes).

## Revogação

- `device.forget` desfaz **uma** relação, a da Pessoa que pede: as
  entregas que chegaram por ela são anuladas, os pedidos por ela falham, e
  os enlaces do dispositivo **ficam** se ele tem outra relação aqui (outra
  Pessoa); se era a última, caem na hora. O outro Duke **não** é avisado:
  o pedido dele por essa relação passa a receber `DENY_NOT_AUTHENTICATED`
  — o aperto da chave fora do registro.
- `device.revoke` e `device.suspend` (do administrador, o estágio 1)
  desfazem a cerimônia em curso com a chave revogada ou suspensa; a lápide
  impede o pareamento — antes e depois do boot.

## O que fica de fora

A descoberta local, a propagação da revogação entre Dukes, a atualização
do endereço, os dispositivos sem tela ou teclado, o pareamento iniciado
por um aplicativo, QR ou câmera, o handoff, os recursos remotos, a
migração ou clonagem de identidade, a atestação, a identidade
compartilhada, a nuvem e a conta central.

## Testes

- **Hospedeiro**: `politica::pareamento` — as derivações (os dois lados
  chegam aos mesmos códigos e ao mesmo `R`; mudar o aperto ou o nonce muda
  tudo; o código se escreve e se lê), o compromisso (o nonce só sai depois
  da 2ª mensagem; o que não confere desfaz), a janela (uma resposta, o
  desafio dela, os prazos), a confirmação (sem o `conferido` do outro, ou
  sem a daqui, nada se grava; o código errado acaba sem segunda vez), a
  desistência durante a gravação, a tabela de transições de cada estado e
  a coerência sob passos sorteados; e o `sigilo`: o prólogo e os quadros
  da cerimônia, que não abrem como enlace nem como agente, e um vetor fixo
  das efêmeras aos códigos e ao `R`.
- **Suíte** (x86 e ARM): 33 casos `pareamento:` — o outro Duke é a suíte,
  com uma chave de teste, iniciando pela vaga do enlace ou aceitando pela
  via do fio da cerimônia, e a Pessoa digita no console. Os dois lados; o
  código errado, expirado, reutilizado; o replay; o par no meio; outro Duke
  no endereço; o dispositivo falso (que alega na carga a chave de outro);
  as mensagens adulteradas e o compromisso errado; a Pessoa sem permissão,
  sem sessão, com o papel que não cabe; a lápide e a suspensão antes, no
  meio e no commit; uma chave, uma espécie; a sessão que não vira enlace;
  parear não autoriza (a interseção a cada pedido: com a relação deixando,
  a Pessoa ou o teto `remoto` sem a intenção recusam, e a auditoria diz
  qual); só pelo teclado; a concorrência — pair × pair, × revoke, ×
  política (no ponto do commit), × suspend, × poweroff, × forget (o
  `device.forget` de outra Pessoa no meio da cerimônia e dentro do
  commit), confirm × expiry, × revoke, × confirm, o commit duplicado —;
  duas Pessoas e o mesmo dispositivo; o `device.forget` (o próprio, o de
  outra Pessoa, e parear de novo); a senha errada na janela de tentativas;
  a auditoria e a proveniência; a meia relação; e o outro que desiste
  depois de este lado gravar.
- **Bancada de duas máquinas** (`cargo xtask pareamento`): dois Dukes de pé
  ao mesmo tempo, e a Pessoa no teclado dos dois — a bancada lê o código de
  cada tela pela árvore semântica e o digita no outro, com a senha. Uma
  ponte do meio no hospedeiro passa os bytes, faz o homem no meio com uma
  chave dela, ou segura o que o destino manda depois do aperto. Os passos:
  B02 o código errado, B03 o homem no meio, B01 a cerimônia e a entrega do
  estágio 1 pela relação, B05 o corte dos dois, B06 esquecer de um lado, B04
  o corte durante a cerimônia (e, depois do boot, nem a relação esquecida
  nem lápide) e a meia relação, B05 a lápide antes e depois do boot. Nos
  quatro pares: x86_64→aarch64, aarch64→x86_64, x86_64→x86_64 e
  aarch64→aarch64 — o par inteiro leva de 4 a 7 minutos no emulador.

## Mutações

Trinta e nove (P01–P39), uma de cada vez, no x86: os testes do hospedeiro
para as que mexem nas contas puras, os casos `pareamento:` para todas, e a
bancada x86_64→x86_64 para as quatro que só o boot de duas máquinas mostra.
**As trinta e nove reprovam.** Na primeira rodada:

- **P26** (a relação pareada decide sozinha, sem a interseção) sobreviveu:
  nenhum caso pedia o que a relação deixa e a Pessoa ou o teto não. O caso
  "parear não autoriza" ganhou a interseção a cada pedido.
- **P34** (a decisão fora do registro do journal) sobreviveu, e era
  equivalente: a decisão passada como 0 a `concluir` ainda entra no mesmo
  registro, porque com 0 ele exige toda a auditoria até a última sequência.
  Reescrita para tirar a decisão de fato — a auditoria da gravação depois
  do `concluir` —, reprova pela conferência do journal.
- **P38** (o 44 reposto como lápide) reprovava só por um sintoma: a
  cerimônia seguinte não mostrava os códigos. A bancada passou a conferir,
  depois do boot do destino, que o esquecido não virou lápide.
- **P08** (o código só do resumo do aperto, sem o nonce) passa pela suíte e
  reprova no hospedeiro: os dois lados da suíte usam a mesma conta pura, e
  só os testes do hospedeiro e o vetor fixo do `sigilo` têm um oráculo de
  fora.
- **P14** não compilou na primeira forma; a refeita reprova.

A campanha também achou uma corrida na suíte: "o desligamento" abria a
cerimônia depois de o fio da energia — meio segundo depois do pedido —
ter entregue a máquina, e a abertura passava. A abertura recusada vai
agora logo depois de um pedido só dela.

## Medidas

- O kernel de produção (release, segmentos carregáveis no arquivo), contra
  o fim do estágio 1 (`488cefe`): x86_64 4 734 707 → 4 860 787 bytes
  (+126 080, +2,66%); aarch64 3 921 647 → 4 050 799 (+129 152, +3,29%).
- A bancada: o par inteiro leva cerca de 380 s no x86_64→x86_64 local e
  240 s no aarch64→aarch64 da CI; os dois pares cruzados, juntos, 12
  minutos na CI. A cerimônia completa (B01, com a entrega do estágio 1 pela
  relação nova), uns 20 s — quase tudo é o teclado do emulador, uma tecla
  de cada vez, conferida na tela antes do Enter.
- Os casos `pareamento:` da suíte, os 33, levam uns 3 minutos no x86.
