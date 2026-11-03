# Os fluxos da malha (DN-2)

Este documento descreve o **DN-2**, o que está implementado e testado: o
**fluxo** — um canal ordenado de bytes, nos dois sentidos, entre dois
processos do mesmo titular —, nesta máquina e entre dois Dukes da mesma
Pessoa. É o terceiro passo da malha: a primeira ([MALHA.md](MALHA.md)) leva
entregas de aplicação a aplicação numa máquina; o enlace
([ENLACE.md](ENLACE.md)) e o pareamento ([PAREAMENTO.md](PAREAMENTO.md))
levam a malha a outro Duke; o fluxo leva **bytes, quantos forem, na
ordem**, por cima dos dois.

O caminho, de ponta a ponta:

```
processo A → gate (stream.open: fabric.stream sobre a intenção [+ fabric.remote sobre o dispositivo])
  → [entre Dukes: fio do fluxo (serviço enlace) → net.connect pelo gate → Noise IK, prólogo do fluxo, quadro 9
     → registro de dispositivos de B → relação → gate de B como o dispositivo, domínio do fluxo]
  → pedido na fila do endpoint → processo B: stream.accept (as duas decisões reconfirmadas)
  → aberto → cada stream.write e cada stream.read pelo gate, no plano de dados
  → fim (finish) / fecho (close) / aborto (revogação, suspensão, morte, exec, desligamento, prazo, protocolo, conexão)
```

**O fluxo não é autoridade.** Abrir não dá nada ao aceitante, e aceitar
não dá nada ao abridor; nenhum token, sessão, chave, arrendamento ou
decisão viaja por ele; os bytes são entrada não confiável para quem os
lê. Cada passo é uma decisão do gate de sempre, pela política de sempre —
e o fluxo é o recurso que essas decisões nomeiam:

```
fluxo → bytes → programa receptor → Gate → operação
```

e nunca `fluxo → autorização`.

## As decisões (DF-1 a DF-6)

As seis decisões do marco, aprovadas antes da implementação:

- **DF-1 — o fluxo é um objeto da malha**, do titular, entre dois
  processos dele: a malha descobre o endpoint, o fluxo leva os bytes. Ele
  nasce **pedido** (pendente na fila do endpoint), abre no **aceite** —
  a abertura efetiva, com as duas decisões reconfirmadas — e acaba.
- **DF-2 — uma permissão nova, `fabric.stream`**, sobre a intenção
  (`intencao:<nome>`), separada de `fabric.send`: mandar uma entrega não
  abre fluxo, e o contrário também não. Abrir, aceitar, ler, escrever,
  terminar, fechar e ver o estado exigem `fabric.stream`, no manifesto e
  no papel.
- **DF-3 — o fluxo aberto é um recurso do plano de dados**: cada
  `stream.write` e cada `stream.read` é uma decisão do gate, gravada, mas
  pelo orçamento do plano de dados — como os `net.*` de uma conexão
  aberta — e não gasta a ficha da taxa de controle. Só o fluxo **aberto
  para quem pede** tem esse orçamento; qualquer outro id cai no de
  controle e na recusa de sempre.
- **DF-4 — um domínio próprio do fluxo entre dispositivos**, no enlace:
  prólogo próprio (`Duke fluxo entre dispositivos v1`), quadro de início
  próprio (tipo 9), o conjunto fechado de mensagens dele, e o crédito por
  sentido. O estágio 1 do enlace e o D8 ficam como estavam.
- **DF-5 — a autoridade remota é a composição já fechada**: Pessoa ∩
  relação ∩ `remoto`, aplicada pelo gate do Duke que recebe como
  `Chamador::Remoto { dominio: Fluxo }`, na abertura **e** na abertura
  efetiva, e depois a cada `dados`. Nenhum segundo gate, nenhuma autoridade
  paralela, nenhuma confiança implícita, nenhum `ALLOW(*)`; o canal Noise
  autentica o Duke, não autoriza nada.
- **DF-6 — as vagas e as conexões partilhadas, com tetos**: as sessões de
  fluxo chegam pelas vagas do enlace (porta 7071), no máximo
  `SESSOES_QUE_CHEGAM` (2) ao mesmo tempo; uma sessão leva **um** fluxo
  (sem multiplexação); no máximo `REMOTOS_POR_RELACAO` (1) aberto por
  relação aqui, e `REMOTOS_QUE_SAEM` (2) daqui a outros dispositivos. A
  origem sai pelo serviço de enlace e pelo gate dela.

## Os comandos

Todos pelo gate, com `fabric.stream`; só um processo abre e aceita.

| Comando | Plano | O que faz |
|---|---|---|
| `stream.open` (`endpoint`, `intent`, `device`, `notify`) | controle | Pede um fluxo ao endpoint que oferece a intenção, de um programa do mesmo titular; com `device`, ao endpoint de outro Duke da Pessoa — decidido aqui com `fabric.remote` sobre `dispositivo:<nome>` e lá pelo gate de lá. Devolve o id. Com `notify`, a ponta de quem abriu avisa no canal de eventos dele (DN-3). |
| `stream.accept` (`endpoint`, `wait`, `notify`) | controle | Aceita o pedido mais antigo num endpoint seu: a abertura efetiva, com a decisão de quem aceita **e a de quem abriu** reconfirmadas na ordem das gravações. Diz quem abriu, como o kernel o conferiu (o programa, ou o dispositivo). |
| `stream.write` (`stream`, `content`/anexo, `wait`) | dados | Escreve no seu sentido o que couber no buffer de 16 KiB; zero com ele cheio; com `wait`, espera espaço, a abertura ou o fim. |
| `stream.read` (`stream`, `max`, `wait`) | dados | Lê o seu sentido, na ordem, até `max`, e `end` depois do último byte; com `wait`, espera um dado ou o fim. |
| `stream.finish` (`stream`) | fecho | Termina o seu sentido: quem lê recebe o resto e o fim; o outro sentido continua. |
| `stream.close` (`stream`) | fecho | Fecha para você: o que você já escreveu segue legível pela outra ponta até o fim do sentido — como o FIN do TCP, também depois de você sair —; o que estava para você ler sai zerado. |
| `stream.status` (`stream`) | controle | O estado, o motivo do fim, os bytes de cada sentido e a outra ponta. |

O id (`<época>:<n>`) **não é capacidade**: só resolve para as duas pontas,
do titular do fluxo; para qualquer outro, a mesma recusa de um id que não
existe. O runtime dos programas (`programas::fluxo`) dá `abrir`,
`abrir_no_par`, `aceitar`, `escrever`, `ler`, `terminar`, `fechar` e
`estado` — e, para o laço do SDK, `abrir_avisando`,
`abrir_no_par_avisando`, `aceitar_avisando`, `ler_agora`,
`escrever_agora` e a `EscritaPendente`.

### O aviso (DN-3)

Com `notify` — o descritor de um canal de eventos do próprio processo —,
`stream.open` e `stream.accept` designam a ponta: as mudanças dela viram
eventos `MALHA` no canal (`a` = 2, a ponta; `b` = o número do id; `c` =
`LEGIVEL`, `GRAVAVEL`, `FIM`). O aviso só sinaliza prontidão: não leva
byte, motivo nem quem, não autoriza nada, e a operação seguinte passa pelo
gate como sempre. É na borda — no máximo um aviso não consumido por ponta,
rearmado pela operação do dono —; `GRAVAVEL` vai só a quem esbarrou no
buffer cheio e a quem abriu, na abertura; e `FIM` sai uma vez. A abertura
pedida ainda não aceita não aceita escrita (`CONFLICT`, "o fluxo ainda nao
abriu"): quem abriu espera o `GRAVAVEL` da abertura. O `exec` larga as
designações antes de abortar os fluxos — a imagem nova não ouve a
anterior. A regra inteira, as medidas e o runtime estão em
[SDK.md](SDK.md).

## Os estados

```
            stream.open                    stream.accept
  (nada) ─────────────▶ pedido ─────────────────────────▶ aberto ──▶ (fim) concluído / fechado pela ponta
                          │  prazo do aceite (30 s)          │
                          │  o endpoint fechou                │  ocioso (120 s sem um byte)
                          │  quem abriu não pode mais         │  revogado, dispositivo revogado/suspenso,
                          ▼                                   ▼  relação desfeita, o processo acabou,
                       (fim)                                (fim) o programa mudou, desligando,
                                                                  protocolo, a conexão caiu, recusa do gate
```

Cada sentido é `aberto → fim` (o `finish` de quem escreve) ou `abortado`;
o fluxo **conclui** quando os dois sentidos acabaram e foram lidos até o
fim — `concluido` — ou `fechado pela ponta` quando uma delas fechou. O
**aborto** — o que o kernel faz na revogação, na suspensão, na morte, no
`exec`, no desligamento, nos prazos, num erro de protocolo ou na queda da
conexão — acaba os dois sentidos na hora, com os buffers zerados, e a
próxima operação de cada ponta ouve o motivo. Depois do fim fica uma
**lápide** (no máximo 32), para cada ponta ver o motivo uma vez.

A ponta é **do processo**: não se herda no `fork`, não sobrevive ao `exec`
(`o programa mudou`) e a morte dele aborta os fluxos de que ele ainda é
ponta (`o processo acabou`). A ponta de que ele já **saiu** — fechou — não
é mais dele: o que escreveu segue legível pela outra até o fim.

## A autoridade

- **Abrir**: `fabric.stream` sobre `intencao:<nome>`, no papel de quem
  pede **e** no manifesto do programa; o endpoint tem de ser do mesmo
  titular e oferecer a intenção — qualquer outro é a mesma recusa. Com
  `device`, também `fabric.remote` sobre `dispositivo:<nome>`, como no
  `fabric.send` do enlace, e o dispositivo tem de ser da Pessoa e não
  estar suspenso.
- **Aceitar** é a abertura efetiva: o kernel decide de novo, **na ordem
  das gravações**, a decisão de quem aceita (o comando em execução) e a de
  quem abriu (o processo, ou o par pela composição remota). O que mudou
  entre o pedido e o aceite recusa ali: `quem abriu nao pode mais`.
- **Ler e escrever**: cada operação é uma decisão do gate sobre a intenção
  do fluxo — a política nova vale na operação seguinte, e a recusa pela
  política encerra o fluxo, com o motivo do gate. Num fluxo com outro
  Duke, cada escrita e cada leitura do processo daqui decide também
  `fabric.remote` sobre o dispositivo.
- **O que chega de outro Duke** é decidido pelo gate daqui como o
  dispositivo (`Chamador::Remoto`, domínio do fluxo, só `stream.open` e
  `stream.write` — o conjunto fechado): a Pessoa da relação ∩ a relação ∩
  o teto `remoto`, com o programa de lá atestado na auditoria. A origem
  não decide como o par o que volta pelo fluxo que o processo dela abriu:
  ela aplica, e o processo lê pelo gate dele.
- **Ninguém decide** o fim, o fecho do par, o crédito e os dados que
  voltam à origem: o kernel aplica e grava.

As chamadas que constroem um `Chamador::Remoto` do fluxo, lançam os fios
do fluxo com a autoridade do serviço de enlace, e chamam os ganchos de
encerramento estão em listas fechadas do `cargo xtask invariantes`
(`CHAMADAS_PROTEGIDAS`, `conferir_os_fluxos`): um caminho novo não passa
sem aparecer ali.

## Entre dois Dukes

**Na origem (A)**, o `stream.open` com `device` deixa o pedido na tabela e
lança o **fio do fluxo**, com a autoridade do serviço de enlace e só ela:

1. `net.connect` ao endereço da relação, pelo gate de A;
2. o Noise IK com a chave do Duke de A, o prólogo do fluxo, no quadro 9 —
   a primeira mensagem não leva carga;
3. o `abrir`, a primeira mensagem de transporte: a relação, o programa de
   A (atestado), o endpoint, a intenção e a época de A;
4. o `aceito` de B: A reconfirma, na ordem, a decisão do processo daqui
   (`fabric.stream` e `fabric.remote`), a relação ativa, o dispositivo não
   suspenso e a máquina não desligando — e o fluxo abre aqui; se não, o
   par ouve o `fechar` com `quem abriu nao pode mais`;
5. os dados, dentro do crédito, cada quadro levado ao `net.send` pelo gate
   em pedaços do buffer da conexão (16 KiB); o fim, o fecho.

**No destino (B)**, a vaga do enlace que recebe um quadro 9 vira, até o
fim, uma sessão de fluxo: acima do teto de sessões, da janela de apertos
ou com a máquina desligando, a recusa vai antes do aperto, sem gastar DH.
Um **fio da sessão**, com a autoridade do serviço de enlace, faz o aperto
— a chave tem de estar no registro de dispositivos e não suspensa —, lê o
`abrir` e o leva ao gate de B como o dispositivo; o pedido entra na fila
do endpoint de lá. Cada `dados` passa primeiro pela conta (o crédito, o
aceite, o fim: passar dela é protocolo) e então pelo gate de B, como um
`stream.write` do dispositivo.

As mensagens, o conjunto fechado do domínio, todas no transporte cifrado:
`abrir` (1), `aceito` (2), `recusado` (3), `dados` (4), `credito` (5),
`fim` (6), `fechar` (7). Qualquer outra coisa — um quadro de outro
domínio, `dados` antes do aceite ou além do crédito, um `abrir`
repetido, um quadro que não decifra — acaba o fluxo com `protocolo`, e o
par ouve o `fechar`. O fim de um lado vem ao outro como `par: <motivo>`.
O que o par mandou antes de saber do fim daqui — o `aceito`, `dados`, o
`credito`, o `fim` que já vinham no caminho — não é protocolo: é
descartado, e o `fechar` leva o motivo daqui.

O **crédito** é por sentido, em bytes: cada lado começa com o buffer do
outro (16 KiB) e devolve crédito à medida que o processo dele lê. A
contrapressão chega a quem escreve sem nenhuma fila crescer: a fila de uma
sessão em B guarda no máximo três buffers, e passar disso acaba a sessão.

## Memória e cotas

| | |
|---|---|
| Buffer de cada sentido | 16 KiB (a maior escrita e a maior leitura também) |
| Fluxos na máquina / por titular / por processo | 16 / 8 / 4 |
| Pedidos na máquina / por endpoint | 16 / 4 |
| Sessões de fluxo que chegam ao mesmo tempo | 2 |
| Fluxos abertos por relação, aqui | 1 |
| Fluxos daqui a outros dispositivos | 2 |
| Lápides | 32 |
| Prazo do aceite / inatividade | 30 s / 120 s |

Passar de uma cota é `DENY_POLICY` com o motivo. O `security.metrics`
mostra os fluxos vivos, os remotos e o pico dos buffers contra o teto.

## Revogação e encerramento

Os ganchos de sempre levam os fluxos, na hora, com o motivo: a pessoa ou a
chave revogada (`revogado`), o dispositivo revogado ou suspenso, a relação
desfeita pelo `device.forget`, a morte do processo, o `exec`, o
desligamento (nada abre, e os vivos acabam), os prazos. Nada se propaga a
outro Duke: o outro lado ouve o `fechar` da sessão, ou vê a conexão cair.

## Auditoria e proveniência

Na cadeia de sempre, **sem o conteúdo** — os bytes nunca vão a registro
nenhum:

- cada decisão do gate (`stream.open`, `stream.accept`, `stream.write`,
  `stream.read`, …), com o programa que pediu;
- na origem: o pedido ao par (`fluxo:<id> ; dispositivo:<nome> ;
  endpoint:… ; intencao:…`, `pedido ao par; politica N`), a abertura
  efetiva pelo kernel (`aberto pelo par; versao V`) — gravada dentro da
  ordem das gravações, antes de acordar quem espera: a operação do
  processo sobre o fluxo, que passa pela ordem, vem depois dela na cadeia —
  e o `net.connect` do serviço de enlace;
- no destino: a sessão (`stream.session`, com a impressão da chave, a
  relação e o atestado do programa de lá), e cada decisão como o
  dispositivo (`pela relacao <R>, atestado <P>`);
- o fim, dos dois lados, em nome do kernel: `stream.end`, com o motivo, os
  bytes de cada sentido e os descartados (`<motivo>; ida N; volta M; desc
  D`) — gravado antes de acordar quem espera, e dentro da ordem das
  gravações quando o fim vem com ela: o pedido pelo processo, e o que vem
  de fora (a inatividade e o prazo do aceite, a revogação, a leitura ou a
  escrita que a política recusa, o fim do processo e o `exec`, o
  desligamento, o endpoint que acaba, o dispositivo ou a relação que sai,
  o aborto da sessão, o que chega do par, o aceite que quem abriu não pode
  mais confirmar). O fim que o envio da sessão conclui é gravado fora da
  ordem (ver os limites do aviso em
  [`SDK.md`](SDK.md#limites-conhecidos)).

A execução que cita a decisão (`…; decisao N`) a cita inteira mesmo
quando o detalhe passa do teto de 96 bytes: quem encolhe é o texto antes
dela. O corte do fim — o de sempre, que a suíte completa achou num
`fs.write` de um processo — deixava `decisao 5587` no lugar de `decisao
55876`, o número de outro registro.

## O que fica de fora

Persistência do fluxo (tudo é volátil: o reboot acaba todos), retomada,
migração e recuperação; fluxo entre titulares; handoff e continuidade;
recursos remotos, descoberta e presença; propagação de revogação; nuvem,
conta central, identidade compartilhada, migração ou clonagem de
identidade e exportação de chaves; multiplexação de fluxos numa sessão.

## Testes

- **Hospedeiro**: `politica::fluxo` — os estados e as transições, os
  sentidos (o fim, o fecho, o aborto, os descartados), a morte de quem só
  terminou (aborta) e a de quem já fechou (não aborta), os prazos, as
  cotas, o crédito com o par e o que cabe dele, o fecho que espera o
  crédito, o retrato, o pico dos buffers, o id que só resolve para as
  pontas, o motivo guardado, a ordem dos bytes e a coerência da tabela sob
  passos sorteados; a permissão `fabric.stream` e a linha da política; e
  no `sigilo`, o quadro 9 como tipo próprio.
- **Suíte** (x86 e ARM): 30 casos `fluxo:`. Os locais — dois programas
  `fluxos` com a autoridade de uma pessoa e a suíte ditando os passos —:
  1 MiB nos dois sentidos, terminar um sentido, fechar com dados
  pendentes, cada lado sem a permissão, o id que não é capacidade, o prazo
  do aceite e o endpoint que fecha, a reconfirmação na abertura efetiva, o
  plano de dados que não gasta a ficha, a contrapressão e as esperas, as
  cotas, a morte (também a de quem já fechou), o `exec` e o `fork`, a
  revogação e a política nova, o desligamento, a inatividade, a auditoria
  sem o conteúdo, os bytes que não autorizam, e as corridas (no meio da
  decisão, ao mesmo tempo, abrir e desligar, muitos fluxos e muitas
  escritas). Os entre Dukes — a suíte faz o outro Duke, com a chave de
  teste de um dispositivo relacionado, chegando pela vaga do enlace de
  verdade ou do outro lado do fio do fluxo —: de ponta a ponta nos dois
  papéis — cada escrita e cada leitura da ponta daqui decidida também
  com `fabric.remote` sobre o dispositivo —, o `abrir` decidido pela
  composição remota, o quadro 9 só no domínio dele, o aperto contra o
  registro (fora dele, revogada, suspensa, a relação de outra pessoa),
  cada `dados` decidido aqui, o protocolo fechado, os tetos das vagas, a
  suspensão, a revogação e a política sem `fabric.remote` com o par —
  também com o aceite, os dados, o crédito ou o fim de lá chegando depois
  do fim daqui, um a cada fim, com os dados de lá depois do fecho daqui,
  quando o fluxo acaba sem lápide, e com o `fechar` de lá e a linha caindo
  logo atrás — e o replay do aperto. E um caso `auditoria:`, a citação da
  decisão inteira acima do teto do detalhe.
- **Invariantes de fonte** (`cargo xtask invariantes`): cada domínio do
  `Chamador::Remoto` sai de um caminho só do enlace, os conjuntos fechados
  são os dois de sempre, os fios do fluxo falam só como o serviço de
  enlace, só os `stream.*`, os ganchos e o coletor mexem na tabela, e o
  plano de dados só reconhece o fluxo aberto, vivo, de quem pede.
- **Bancada de duas máquinas** (`cargo xtask fluxo`): dois Dukes de pé e
  uma ponte do meio no hospedeiro. FB01, 4 MiB em cada sentido, local;
  FB02, entre os Dukes, com a auditoria dos dois lados e nenhum byte do
  conteúdo nela; FB03, a contrapressão de um leitor lento e o pico dos
  buffers; FB10, a ponte troca um bit de um quadro de dados; FB09, o
  homem no meio com uma chave da ponte; FB06, a política nova no meio do
  fluxo; FB05, a suspensão e o `device.forget`; FB07, o corte de energia
  do destino, e depois do boot nada do fluxo; FB08, as vagas da 7071 com
  outro dispositivo que a bancada faz; FB04, a revogação dos dois lados.
  Nos quatro pares.

## Mutações

Cinquenta e seis mutações — F01 a F55 e a F32b —, uma de cada vez, no
repositório, no x86_64, com o controle sem mutação passando em tudo antes:
as da conta pura (`politica::fluxo`, `dispositivos`, `arquivo`,
`auditoria`) rodam os testes do hospedeiro; as do kernel, os 30 casos
`fluxo:` da suíte (com os `enlace:` quando mexem no domínio do
`Chamador::Remoto`); a F32 e a F33, as invariantes de fonte; a F43 e a
F44, a bancada x86_64→x86_64 — e a F44, por fim, também a suíte —; a F50 e
a F55, o caso `auditoria:` da citação. Na primeira rodada de cada uma
sobreviveram sete, todas por fraqueza dos testes, e não do código: a F19 e
a F20 (os restos do aborto e do encerramento sem conta), a F42
(`fabric.remote` fora das decisões do plano de dados), a F51, a F52 e a
F53 (as mensagens do par depois do fim daqui) e a F44 (o envio que falha
com o `fechar` do par já na fila). Para as seis primeiras, os testes foram
reforçados no commit `a7d8031`: os do hospedeiro olham os restos; o caso
de ponta a ponta para outro Duke confere o recurso de cada decisão de
escrita e de leitura; o da suspensão e da revogação do par ganhou a
política sem `fabric.remote` e um fim daqui para cada mensagem tardia.
Cinco caíram. A F53 ainda passou: na origem, os dados de lá que chegam
depois do fim daqui acham a lápide do fluxo e dão `Encerrado`, e a F53 só
mexe no outro ramo, o `NaoExiste` — o fluxo que acaba sem lápide, porque a
ponta daqui já tinha saído. O caso ganhou esse fim no commit `f8c29b0`: a
ponta daqui fecha com três bytes esperando o crédito de lá, a suspensão
acaba o fluxo, e os dados de lá chegam depois. A F44 passou pela bancada
porque a corrida não aconteceu: no x86_64→x86_64, a origem sempre leu o
`fechar` do par antes de mandar. O mesmo caso a faz de propósito, no
commit `691a0b2`: o par manda o crédito e o `fechar` e a linha cai, tudo
antes de a sessão acordar — ela manda, o envio falha sempre, e o fluxo tem
de acabar com o motivo do par. A F32b é a troca da F32 escrita para a
suíte ver. O veredito abaixo é o da última rodada de cada uma: nenhuma
sobrevive.

| | Mutação | Reprovada por |
|---|---|---|
| F01 | stream.open exige outra permissão (system.read) e não fabric.stream | suíte — `fluxo: abrir, aceitar e 1 MiB nos dois sentidos, entre programas`, `fluxo: terminar um sentido, e o outro continua`, `fluxo: fechar com dados pendentes` |
| F02 | stream.accept exige outra permissão (system.read) | suíte — `fluxo: abrir, aceitar e 1 MiB nos dois sentidos, entre programas`, `fluxo: terminar um sentido, e o outro continua`, `fluxo: fechar com dados pendentes` |
| F03 | o aceite não reconfirma quem abriu | suíte — `fluxo: sem a permissao, cada lado e recusado`, `fluxo: a reconfirmacao na abertura efetiva` |
| F04 | o aceite sem reconfirmar a própria decisão (em_ordem sem reconfirmar) | suíte — `fluxo: a reconfirmacao na abertura efetiva`, `fluxo: as corridas no meio da decisao` |
| F05 | stream.write exige outra permissão (system.read) | suíte — `fluxo: abrir, aceitar e 1 MiB nos dois sentidos, entre programas`, `fluxo: terminar um sentido, e o outro continua`, `fluxo: fechar com dados pendentes` |
| F06 | stream.read exige outra permissão (system.read) | suíte — `fluxo: abrir, aceitar e 1 MiB nos dois sentidos, entre programas`, `fluxo: terminar um sentido, e o outro continua`, `fluxo: fechar com dados pendentes` |
| F07 | o plano de dados aberto para quem já saiu do fluxo | hospedeiro — `o_id_so_para_as_pontas` |
| F08 | o plano de dados aberto para o pedido que ainda não abriu | hospedeiro — `o_id_so_para_as_pontas` |
| F09 | o endpoint de qualquer titular abre fluxo | suíte — `fluxo: o id nao e capacidade`, `fluxo: o abrir de outro Duke decidido pela D4` |
| F10 | o id vale para outro titular (o id como capacidade) | hospedeiro — `o_id_so_para_as_pontas` |
| F11 | a escrita do par sem o crédito | hospedeiro — `o_credito`, `o_que_cabe_do_par`, `o_pico_dos_buffers` |
| F12 | o buffer do sentido sem limite (livre ignora o que há) | hospedeiro — `o_pico_dos_buffers`, `a_ordem_por_sorteio` |
| F13 | a cota da máquina (16) passa por um | hospedeiro — `as_cotas` |
| F14 | a cota do titular (8) passa por um | hospedeiro — `as_cotas`, `coerente_por_sorteio` |
| F15 | a cota do processo (4) passa por um, no abrir e no aceitar | hospedeiro — `as_cotas`, `coerente_por_sorteio` |
| F16 | a fila do endpoint (4 pedidos) passa por um | hospedeiro — `as_cotas`, `coerente_por_sorteio` |
| F17 | escreve depois de terminar o próprio sentido | hospedeiro — `os_sentidos` |
| F18 | quem fecha não perde o que estava para ele ler | hospedeiro — `fechar_e_abortar`, `o_credito`, `o_que_cabe_do_par` |
| F19 | o sentido abortado não zera nem conta o que havia | hospedeiro — `fechar_e_abortar` |
| F20 | o encerramento não zera nem conta os restos | hospedeiro — `o_encerramento_conta_os_restos` |
| F21 | a revogação do titular não encerra os fluxos dele | suíte — `fluxo: a revogacao e a politica nova encerram`, `fluxo: as corridas no meio da decisao` |
| F22 | a morte do processo não encerra os fluxos dele | suíte — `fluxo: a contrapressao e as esperas`, `fluxo: a morte, a troca de imagem e a bifurcacao`, `fluxo: as corridas no meio da decisao` |
| F23 | a troca de imagem não encerra os fluxos do processo | suíte — `fluxo: a morte, a troca de imagem e a bifurcacao` |
| F24 | o dispositivo que sai (revogado, suspenso) não encerra os fluxos com ele | suíte — `fluxo: a suspensao e a revogacao do par` |
| F25 | a suspensão do par encerra com o motivo da revogação | suíte — `fluxo: a suspensao e a revogacao do par` |
| F26 | o endpoint que acaba não encerra os pedidos nele | suíte — `fluxo: o prazo do aceite e o endpoint que fecha` |
| F27 | com o desligamento pedido, o fluxo local ainda abre | suíte — `fluxo: com o desligamento, nada abre e os vivos acabam`, `fluxo: abrir e desligar ao mesmo tempo` |
| F28 | o pedido não vence o prazo do aceite | hospedeiro — `os_prazos` |
| F29 | o fluxo ocioso não acaba | hospedeiro — `os_prazos` |
| F30 | a relação desfeita (device.forget) não encerra os fluxos por ela | suíte — `fluxo: cada dados de outro Duke decidido aqui` |
| F31 | os dados do par aplicados em B sem passar pelo gate de B | suíte — `fluxo: de outro Duke, pela vaga do enlace, de ponta a ponta`, `fluxo: cada dados de outro Duke decidido aqui` |
| F32 | o domínio do enlace aceita os métodos do fluxo | invariantes — a invariante do domínio |
| F33 | o domínio do fluxo aceita os métodos do enlace | invariantes — a invariante do domínio |
| F34 | o canal do agente aceita o quadro 9 como aperto | suíte — `fluxo: o quadro 9 so no dominio dele` |
| F35 | a origem aperta com o prólogo do enlace | suíte — `fluxo: para outro Duke, pelo fio do fluxo, de ponta a ponta`, `fluxo: a suspensao e a revogacao do par` |
| F36 | o destino aceita o aperto com o prólogo do enlace | suíte — `fluxo: de outro Duke, pela vaga do enlace, de ponta a ponta`, `fluxo: o abrir de outro Duke decidido pela D4`, `fluxo: o quadro 9 so no dominio dele` |
| F37 | a revogação do dispositivo não o tira do registro (a lápide sem efeito) | hospedeiro — `a_desfeita_reposta_e_idempotente_e_a_lapide_ainda_barra`, `a_lapide_e_permanente`, `coerente_sob_operacoes_sorteadas` |
| F38 | o dispositivo suspenso passa o aperto do fluxo | suíte — `fluxo: para outro Duke, pelo fio do fluxo, de ponta a ponta`, `fluxo: o aperto com o par confere o registro` |
| F39 | o teto de sessões que chegam (2) passa por um | suíte — `fluxo: os tetos das vagas do enlace` |
| F40 | a sessão do par fora da auditoria (sem stream.session) | suíte — `fluxo: de outro Duke, pela vaga do enlace, de ponta a ponta` |
| F41 | o fim gravado sem o motivo | suíte — `fluxo: abrir, aceitar e 1 MiB nos dois sentidos, entre programas`, `fluxo: terminar um sentido, e o outro continua`, `fluxo: fechar com dados pendentes` |
| F42 | a escrita e a leitura de um fluxo remoto sem a decisão do dispositivo | suíte — `fluxo: para outro Duke, pelo fio do fluxo, de ponta a ponta`, `fluxo: a suspensao e a revogacao do par` |
| F43 | o quadro de dados cheio num net.send só (passa do buffer da conexão) | bancada (x86_64→x86_64) — FB02: a troca de 4 MiB entre os Dukes não fechou, a conexão caiu no primeiro quadro cheio |
| F44 | a origem não lê o fechar do par quando o envio falha | suíte — `fluxo: a suspensao e a revogacao do par` (a bancada x86_64→x86_64 não a viu: a corrida não aconteceu) |
| F45 | o orçamento do plano de dados para um fluxo que não está aberto | suíte — `fluxo: o plano de dados nao gasta a ficha` |
| F46 | a relação: um segundo fluxo do mesmo par ao mesmo tempo | hospedeiro — `as_cotas`, `coerente_por_sorteio` |
| F47 | fluxos que saem a outros dispositivos passam do teto (2) | hospedeiro — `as_cotas`, `coerente_por_sorteio` |
| F48 | a morte de quem já fechou aborta o fluxo (o fecho não sobrevive à morte) | hospedeiro — `fechar_e_abortar` |
| F49 | fabric.stream sem o alcance de intenção (a linha `*` passa: ALLOW(*)) | hospedeiro — `a_confianca_muda_dentro_do_teto`, `a_decisao_por_todos`, `a_cota_do_armazem` |
| F50 | o detalhe composto corta o fim, com a citação da decisão junto | hospedeiro — `o_detalhe_composto_guarda_a_citacao` |
| F51 | o crédito que chega depois do fim daqui é protocolo | suíte — `fluxo: a suspensao e a revogacao do par` |
| F52 | o fim de lá que chega depois do fim daqui é protocolo | suíte — `fluxo: a suspensao e a revogacao do par` |
| F53 | os dados de lá que chegam à origem depois do fim daqui são protocolo | suíte — `fluxo: a suspensao e a revogacao do par` |
| F54 | o aceite que chega depois do fim daqui encerra a sessão sem o fechar | suíte — `fluxo: a suspensao e a revogacao do par` |
| F55 | a execução do processo cola a citação no texto (o corte do anel a leva) | suíte — `auditoria: a citacao da decisao fica inteira acima do teto` |
| F32b | o domínio do enlace aceita os métodos do fluxo | suíte — `fluxo: para outro Duke, pelo fio do fluxo, de ponta a ponta` |

## Medidas

**O tamanho do kernel** de release, nos segmentos carregados, contra o
D8: x86_64, de 4 860 787 para 5 138 155 bytes (+277 368, +5,7%); aarch64,
de 4 050 799 para 4 298 347 (+247 548, +6,1%). Na memória, +278 760 e
+259 636.

**A vazão na bancada** — QEMU sem KVM, dois núcleos por máquina, as duas
no mesmo hospedeiro de quatro núcleos; 4 MiB em cada medida. Cada leitura
e cada escrita é uma decisão do gate e um registro da auditoria, em
pedaços de até 16 KiB: é o custo de nenhum byte passar sem decisão, e não
o do transporte.

| Par (origem→destino) | Local, ida / volta | Entre os Dukes, ida / volta | Leitor lento |
|---|---|---|---|
| x86_64→x86_64 | 149 / 194 KiB/s | 105 / 97 KiB/s | 43 KiB/s |
| x86_64→aarch64 | 146 / 185 KiB/s | 98 / 91 KiB/s | 38 KiB/s |
| aarch64→x86_64 | 142 / 166 KiB/s | 98 / 84 KiB/s | 42 KiB/s |
| aarch64→aarch64 | 150 / 171 KiB/s | 107 / 89 KiB/s | 40 KiB/s |

O pico dos buffers, nos dois lados do leitor lento, ficou no teto (16 384
bytes) e não passou dele. O par inteiro, os dez passos, leva de 624 a
709 s.
