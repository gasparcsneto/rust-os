# Tecido nativo de segurança (NSF)

> **Estado: em implementação.** Este texto foi escrito antes da primeira
> linha, a partir do que o kernel já é, e diz os contratos que o código
> cumpre. Ver [Incrementos e estado](#incrementos-e-estado) no fim.

## O que é

O NSF observa, correlaciona e interpreta o que acontece no Duke: pessoas,
agentes, credenciais, processos e os filhos deles, a rede, o firewall, o
armazenamento, o TPM, a política. Ele monta a cadeia causal do que viu,
avalia o risco, detecta padrões de ataque, abre incidentes com evidência
verificável e **pede** respostas. Ele não decide nada sobre acesso.

A cadeia de autoridade continua uma só:

```text
identidade → autoridade → política → gate → recurso
```

e o NSF entra nela como entra qualquer outro principal: com uma
identidade própria, um papel que a política enumera, e cada leitura e cada
ação pedidas ao gate, gravadas na auditoria, recusáveis.

## A regra de ouro

```text
O gate decide.
A auditoria registra.
O NSF observa, correlaciona, interpreta, detecta, avalia o risco e abre
  incidentes.
O motor de resposta pede ações.
O gate decide se a resposta pode acontecer.
A auditoria registra a resposta.
O NSF observa o resultado.
```

Nenhum componente do NSF:

- passa ao lado do gate, nem cria uma segunda autorização;
- trata o `sistema` como curinga — o papel dele continua enumerado;
- muda permissões, papéis ou a política;
- lê um recurso protegido sem uma permissão escrita na política;
- tem exceção por ser "de segurança", nem dá exceção a agentes de IA;
- transforma detecção ou risco em autorização;
- usa o DNS, o firewall ou a si mesmo para escapar do gate;
- depois de uma recusa do gate, procura outro caminho para o mesmo efeito.

## O NSF como principal

| | O que é | Onde mora |
|---|---|---|
| **Identidade** | o serviço `nsf` — um nome de um vocabulário fechado, como as permissões | `politica::arquivo::SERVICOS` |
| **Autoridade** | `Autoridade::Servico(Servico::Nsf)`: a de um fio do kernel que nasce com ela, e que nenhum processo, agente ou pessoa recebe | `autorizacao::Autoridade` |
| **Papel** | o da linha `servico nsf <papel>` da política — na imagem, `seguranca` | a política |
| **Permissões** | as que o papel enumera, nada além: `audit.read`, `net.observe` e `net.block`, com o alcance de cada uma escrito | a política |
| **Titular na auditoria** | `service`, identificador `nsf` | `politica::auditoria::Titular::Servico` |
| **Taxa** | um balde próprio, pela linha `taxa` do papel — o de cada serviço, e não um para todos: o serviço de hora tem o dele | `autorizacao::Principal::Servico` |

A linha `servico` só vem da imagem (um `policy.write` não a escreve), e a
política que a tem só vigora se o papel do serviço **não** for o da serial,
o da autoridade local ou um teto de administrador: o NSF não herda o
`sistema` nem o que um administrador delega. Sem a linha, o NSF não tem
papel, e o gate recusa cada pedido dele (`DENY_ROLE`, gravado): ele fica
cego e inerte, e não "com tudo" — falha fechado.

Os pedidos do NSF chegam ao gate como os de um processo:
`Chamador::Processo { fio, autoridade: Servico, programa: Kernel }`, pelo
mesmo `nativo::responder_como` que atende os programas — a validação dos
parâmetros, a decisão, o envelope e a auditoria são os mesmos. Os comandos
"só do canal" (`admin.*`, `debug.trigger`) recusam o NSF como recusam um
processo: ele não tem prova de administrador, e não tem como ter.

## Como o NSF observa

Só por leituras decididas pelo gate, com o papel dele:

| Leitura | Permissão | O que traz |
|---|---|---|
| `audit.tail {after, count}` | `audit.read` | os registros da cadeia depois de `after`, com o elo de cada um |
| `net.observe {to, after, max}` | `net.observe`, alcance: destinos enumerados | os datagramas trocados com o destino `to` — o conteúdo —, de associações de qualquer titular |

Não há gancho no funil da auditoria, nem cópia dos registros por fora: o
NSF lê a auditoria pelo mesmo comando que uma pessoa usa, e cada leitura
dele é um registro da cadeia (`service nsf audit.tail ALLOW`). Tirar
`audit.read` do papel `seguranca` deixa o NSF cego, e a recusa fica
gravada.

O único sinal que o NSF recebe fora do gate é um **contador**: o número do
último registro da auditoria, que o fio dele olha para saber se há o que
ler — um despertador, sem conteúdo, que não decide nada. É o que deixa a
auditoria quieta quando nada acontece: o NSF só lê quando a cabeça passou
da última leitura dele, e a leitura dele é o último registro.

A cada volta, a auditoria primeiro, a captura depois. O servidor de DNS
que o NSF observa ele aprende pela auditoria — o `net.connect` que alguém
fez a ele, e o gate deixou —, e um programa rápido abre a associação,
resolve e conecta antes de uma volta: lida a captura antes, a resposta
daquele servidor ficaria para trás. Por isso a captura vem depois, e a
regra do DNS liga a resolução à conexão nas duas ordens — a conexão
procura a resolução que a precedeu, e a resolução, lida depois, procura as
conexões que ela precedeu. A captura só se dá por vista quando a leitura
da auditoria alcançou a cabeça de antes dela: um servidor que a volta
ainda não conhecia é lido na seguinte.

O que a auditoria não tinha e o NSF precisa entra **na auditoria**, nos
pontos onde acontece — não num canal paralelo:

- o processo que nasceu: o `user.run` grava, como execução da decisão
  dele, o fio do filho (`processo N lancado; decisao D`), e o `bifurcar`
  grava o filho (`process.fork`) em nome do pai — os dois **antes de o
  filho poder rodar**, para que o primeiro pedido dele nunca chegue antes
  do registro que diz quem o criou. O `process.fork` é um fato, não uma
  decisão: bifurcar não é permissão (o filho herda a autoridade do pai, e
  conta na cota dela), e tudo o que o filho pedir passa pelo gate;
- a conexão derrubada por um bloqueio, como execução do `net.block`;
- o pedido de rede recusado pelo firewall, como execução da decisão que o
  gate tinha permitido.

O conteúdo de um datagrama nunca vai para a auditoria (ela guarda resumos,
não corpos): vai para o anel de captura, que só `net.observe` lê, e só
para destinos que a política diz observáveis — um destino entra no anel se
algum papel tem `net.observe` com ele no alcance.

## O caminho

```text
observação → correlação → detecção → investigação → risco → incidente
           → resposta → verificação
```

| Etapa | O que faz | Onde |
|---|---|---|
| Observação | lê a auditoria e a captura pelo gate; refaz cada elo da cadeia | `kernel::seguranca` (o fio), `seguranca::evento` |
| Modelo de evento | um registro → um evento de segurança, com proveniência | `seguranca::evento` |
| Correlação | eventos → cadeias causais, por identificador de correlação | `seguranca::correlacao` |
| Grafo causal | pessoas, agentes, credenciais, sessões, processos, filhos, programas, recursos, destinos, nomes, decisões, incidentes | `seguranca::grafo` |
| UEBA | perfil de comportamento de cada principal, determinístico | `seguranca::ueba` |
| Risco | pontuação explicável por principal | `seguranca::risco` |
| Detecção | regras nomeadas sobre a sequência; e o monitor de invariantes | `seguranca::regras`, `seguranca::invariantes` |
| Incidente | atores, eventos, recursos, evidência, risco, detecções, estado, ações | `seguranca::incidente` |
| Evidência | cofre com cadeia de resumos própria, ligada aos elos da auditoria | `seguranca::evidencia` |
| Resposta | planeja pedidos; nunca executa | `seguranca::resposta` |
| Execução | pede ao gate, com a identidade do NSF, e grava o desfecho no incidente | `kernel::seguranca` |
| Verificação | o resultado volta pela auditoria e fecha o ciclo | `seguranca::resposta` |

O motor (`seguranca`, um pacote `no_std` testado no hospedeiro) é uma
função da sequência de eventos: o tempo vem dos registros (`ts_ms`), nunca
de um relógio, e a mesma auditoria dá os mesmos incidentes. É isso que faz
a reprodução: no boot, o NSF lê a janela da auditoria que o journal repôs
— a do boot anterior incluída — e refaz o estado, sem pedir resposta
nenhuma para o que é história.

### O modelo de evento

| Campo | De onde vem |
|---|---|
| identidade do ator | `holder`, `agent`, `key`, `person_session` do registro |
| identidade do processo | o prefixo `pelo processo N (programa resumo)` do detalhe |
| criador | o grafo: a aresta `lançou` ou `bifurcou` que chega ao processo |
| autoridade | o titular e a sessão: agente pela chave, pessoa pela sessão, sistema, serial, serviço |
| credencial | a chave do agente, a pessoa, a prova do administrador, ou nenhuma |
| operação, recurso | `method`, `resource` |
| escopo | o papel (`role`) |
| decisão do gate, resultado | `code` e `result`; `decisao D` no detalhe de uma execução |
| tempo | `ts_ms` — o tempo lógico da persistência |
| correlação | a raiz da cadeia causal do ator |
| proveniência | a cadeia de criadores até a raiz |
| severidade | a da regra que o envolveu; `info` sem nenhuma |
| referência de evidência | a sequência e o elo do registro; o item do cofre |

As entidades de um boot não se confundem com as de outro: o `policy.load`
do kernel abre uma época, e um processo é `(época, fio)`.

### Risco e UEBA

O risco de um principal é uma soma de fatores com teto, cada um com o
motivo — as recusas da janela, as tentativas fora do alcance, as permissões
sondadas, as falhas de autenticação, as detecções abertas, a anomalia do
perfil. O perfil de comportamento (UEBA) é contado em aritmética inteira:
os métodos, a proporção de recusas, os recursos distintos, a taxa contra a
linha de base. O tempo das contas é o dos registros: o relógio lógico da
auditoria, de um segundo — uma duração ganha uma resolução, porque dez
pedidos com o mesmo carimbo cabem num segundo, e não num milissegundo; e
a taxa da linha de base espera trinta segundos de história, porque a
rajada dos primeiros pedidos de quem acabou de chegar não é o ritmo dele.
Os dois são **contexto**: aparecem no incidente, ordenam o
que um humano olha, e a única coisa que mudam é o que o NSF *pede* — e o
gate decide o pedido como decidiria o de qualquer um. Um aprendizado de
máquina que entre um dia no lugar da conta inteira entra no mesmo lugar, e
continua sem autoridade.

### As regras

Cada uma tem nome, severidade e explicação, e aponta os eventos que a
dispararam:

| Regra | Dispara com |
|---|---|
| `privilege-probing` | recusas por permissão — do papel — em métodos distintos, do mesmo ator, numa janela |
| `outside-manifest` | um programa pediu o que o manifesto dele não declara: o papel de quem o lançou tem a permissão, e a atenuação recusou — um sinal do programa, médio, que não conta como sondagem de quem o lançou |
| `credential-abuse` | recusas de autenticação da mesma identidade: chave revogada, sessão que acabou, login recusado |
| `out-of-scope` | recusas de recurso repetidas do mesmo ator |
| `policy-change` | mudança de política ou de papel executada; recusas de mudança repetidas |
| `anomalous-behavior` | o perfil do ator saiu da linha de base — para pessoas e agentes de IA, pela mesma conta |
| `firewall-evasion` | pedidos recusados pelo firewall repetidos, ou insistência num destino bloqueado |
| `dns-against-policy` | um nome resolvido para um endereço que o gate recusa a quem resolveu |
| `process-chain` | processos lançados em profundidade ou em rajada a partir do mesmo ator |
| `ceiling-exercised` | tentativa de exercer o papel de teto de um administrador |
| `egress-after-probing` | quem tem um incidente alto aberto usa a rede |
| `code-tampered` | o código de fora da imagem cujo selo não confere com ele — os bytes mudaram depois de selados, ou o selo é forjado: basta uma vez, mas quem pediu pode ser a vítima, e a confiança é média; o NSF não planeja contenção por ela — alerta, e a contenção fica com quem tem a autoridade. O código sem selo e o editor em quem o papel não confia são política, e não disparam nada |
| `clock-jump` | o relógio civil saltou dentro do envelope da incerteza, ou na primeira sincronização — a gravidade pelo tamanho, a confiança baixa: é o relógio sendo corrigido |
| `clock-jump-beyond-envelope` | o salto que a incerteza não explica: o contador derivou, ou as fontes se moveram juntas |
| `clock-jump-pending` | o salto acima do teto, ou para trás fora do envelope, que só uma pessoa confirma: recomenda `time.confirm {round}` com a rodada dele |
| `time-source-divergent` | uma fonte fora do acordo da rodada, com os vereditos dela como evidência |
| `time-source-bad-signature` | uma resposta que a chave fixada da fonte não fecha — forjada, ou a chave trocada —, uma vez por fonte até ela ser aceita de novo |
| `time-unauthenticated` | a hora autenticada venceu; ou três rodadas de um boot sem hora autenticada, como observação |
| `logical-clock-stopped` | o tempo lógico parado à frente do civil, uma vez por parada |

As de tempo leem os registros de `time.sync` e `time.confirm` (ver [O
tempo](#o-tempo-t73-a-t75)); o principal delas é o relógio, `clock`, e não o
serviço de hora.

E o **monitor de invariantes** — a segunda camada, sobre o que as regras
não olham: o elo de cada registro lido refaz a conta da cadeia; a
sequência não tem buraco não declarado; o tempo não volta; e toda ação do
próprio NSF que a auditoria mostra corresponde a um pedido que o motor
planejou. Uma ação do NSF sem plano é uma detecção crítica. As violações
são `audit-tampered`, `audit-gap`, `time-goes-back` e
`unplanned-nsf-action`.

### O incidente

Atores, eventos, registros da auditoria, recursos afetados, evidência,
risco, detecções, estado (`aberto`, `contido`, `encerrado`), e as ações —
cada uma com o pedido, o nível, a decisão do gate (a sequência e o código)
e a identidade que a autorizou. Uma ação que um humano faz pelo próprio
papel — um `net.block` da serial sobre um destino do incidente — entra no
incidente como ação dele.

### O cofre de evidências

Uma cadeia de resumos própria, como a da auditoria e com outro rótulo:

```text
elo(n) = BLAKE2s("Duke evidencia v1" || elo(n-1) || codificacao(n))
```

Cada item aponta o que prova: um registro da auditoria (a sequência e o
**elo dela** — o cofre se amarra à cadeia que o gate escreveu), um
datagrama capturado (o resumo dos bytes e o tamanho), uma detecção, uma
ação. `security.verify` refaz a cadeia. O cofre complementa a auditoria;
não a substitui, e não guarda nada que ela devesse guardar.

## A resposta

| Nível | O que é | Quem autoriza |
|---|---|---|
| 0 — Observar | o NSF registra e correlaciona | — |
| 1 — Alertar | o incidente aparece em `security.incidents`, com a recomendação | — |
| 2 — Resposta autorizada | quem tem a permissão executa a recomendação pelo próprio papel (`net.block` pela serial, por exemplo) | o gate, sobre o papel de quem pede |
| 3 — Contenção automática pré-autorizada | o NSF executa a contenção sozinho | o gate, sobre o papel `seguranca` — o que a política deixou o NSF fazer, e só isso |

A pré-autorização é a política: o NSF só **consegue** bloquear um destino
que o alcance de `net.block` do papel dele enumera. Ele pede; uma recusa
fica gravada no incidente com o código, e o objetivo daquela ação é
encerrado — o motor não planeja outra ação para o mesmo efeito, nem com
outro comando, nem com outro alvo. O que só um administrador faz com prova
— revogar uma credencial, encerrar a sessão de um agente — o NSF
**recomenda** (nível 1): ele não tem prova, e o caminho até a operação
exige uma.

## O firewall nativo

```text
gate → operação de rede → firewall → rede
```

O firewall é controle de tráfego, não uma segunda política: não tem regra
que permita. Um pacote só sai se o gate decidiu a conexão dele **e** o
firewall não o barra; um destino que o gate recusa não chega a ter tráfego
para o firewall olhar. Nenhum conflito entre os dois abre passagem: ou os
dois deixam, ou não passa.

- **Estrutural.** Cada quadro que a pilha manda pertence a uma conexão da
  tabela — a mesma que o gate decidiu —, ou ao DHCP da própria placa; o
  resto não sai. Cada quadro que chega vai a uma porta local de uma
  conexão do mesmo protocolo (no TCP, com a quádrupla inteira), ao DHCP,
  ou — só o SYN — à escuta do canal do agente; o resto é descartado antes
  da pilha — sem RST, sem eco ICMP. A escuta só responde com o SYN-ACK ou
  o RST. O ARP passa.
  Contado em `net.rules`, em cada sentido: sem fluxo, de fluxo barrado, de
  protocolo que não passa.
- **Regras.** `net.block {to, owner?}` barra um destino — para todos, ou só
  para um agente (pela chave), uma pessoa (pela sessão) ou um processo
  (pelo fio). É um comando do registro: o gate o decide pela permissão
  `net.block` e pelo alcance enumerado dela, e grava. As conexões vivas que
  a regra alcança são derrubadas, cada uma gravada como execução do
  bloqueio — e nem o aviso delas sai (o RST de uma conexão TCP derrubada
  é um quadro do fluxo barrado: o destino contido não fica sabendo pela
  rede); `net.connect` e `net.send` num fluxo barrado são recusados com
  o número da regra, gravados como execução da decisão que o gate tinha
  permitido. `net.unblock` tira a regra — e o gate continua decidindo cada
  pedido, como antes dela.
- **O número da conexão cortada.** A conexão que a regra derrubou some da
  rede, mas o número dela continua do dono, cortado, até ele o fechar ou
  acabar: o pedido seguinte sobre ele — um `net.send`, um `net.recv`, o
  que acordou de uma espera — é decidido pelo gate como qualquer outro (a
  autoridade, a contenção e a revogação de quem pede vêm primeiro), e a
  execução ouve a regra que cortou: `FIREWALL_BLOCKED`, com a regra,
  gravado como execução da decisão `ALLOW`. Antes, o número sumia junto,
  e o pedido seguinte ouvia `DENY_RESOURCE` — a recusa da política para
  um recurso que não é de quem pede — quando quem barrou foi o firewall.
  O HTTP pegou (ver abaixo). O número cortado conta no teto do dono, como
  uma conexão que o outro lado fechou; o `net.close` o solta, e o coletor
  o esquece quando o dono acaba, sem registro novo — o corte já foi
  gravado.

Na tabela da pilha, ao lado dos fluxos que controlam; as regras não vão ao
journal (ver [limitações](#limitacoes-deliberadas)).

## O DNS (9.4)

O DNS é um **programa** sobre a associação UDP do 9.3: monta a pergunta,
manda pela associação com o servidor (`udp:<servidor>:53`, que o gate
decide), lê a resposta e a entende — `protocolo::dns`, o mesmo codec que o
agente de fora usa. O kernel não resolve nomes: não há `net.resolve`, e um
nome não é recurso da política.

Uma resposta de DNS não dá acesso a nada. O endereço que ela traz é só um
número na mão do programa; para conversar com ele, o programa pede
`net.connect` com o destino inteiro, e o gate decide esse destino como
decidiria se o número tivesse sido digitado. Um nome que resolve para um
destino fora do alcance dá `DENY_RESOURCE`, como o destino daria.

A recusa no meio do DNS também é do gate, com o código dele. A associação,
a pergunta e a leitura da resposta são pedidos como os outros, e o
programa contido, revogado ou sem sessão ouve `DENY_CONTAINED`,
`DENY_ROLE` ou `DENY_NOT_AUTHENTICATED` — e não `DENY_POLICY` sempre, nem
"o DNS não respondeu", como a primeira versão dizia quando a recusa vinha
na pergunta ou na leitura. O HTTP pegou: a cadeia inteira começa pelo
DNS, e a revogação no meio dela chegava como um servidor mudo.

O NSF vê o DNS pela captura (`net.observe` sobre o servidor): entende a
resposta com o mesmo codec — num lugar só, o fio dele — e liga o nome ao
endereço, o endereço à conexão pedida em seguida pelo mesmo dono, e a
conexão à decisão do gate. É o que responde "que resolução precedeu esta
conexão, e o endereço passou de novo pelo gate?".

"Precedeu" é a ordem da auditoria, e não a do relógio, que é de um
segundo: cada datagrama guardado leva o número do último registro da
auditoria naquele instante (`after_record` no `net.observe`), e uma
resolução precedeu a decisão de número maior que esse. Sem conteúdo — um
número —, e exato onde o relógio não separaria as duas.

A captura de cada servidor é lida de onde parou, em lotes de 16, e a
volta segue lendo enquanto o lote vem cheio — até o anel inteiro: o fim de
uma rajada não espera outro datagrama, que talvez não venha. A primeira
versão lia um lote por volta, e o resto só quando um datagrama novo
chegasse; o programa que resolve muitos nomes de uma vez deixava as
últimas respostas sem ninguém ler até alguém usar o DNS de novo. O HTTP
pegou: os casos dele enchem o anel antes dos do DNS. O NSF que começa do
agora — o da suíte, entre um caso e outro — também não lê a captura de
antes dele: o servidor que ele passa a observar começa de onde o agora
começou, e não do começo do anel, que guarda a conversa de outros donos,
com números que um processo de agora pode ter de novo.

A bancada da suíte tem um servidor de DNS determinístico, dentro da
máquina, num endereço que o emulador não tem (`10.0.2.53`): uma tabela que
o caso escreve, e modos para mentir de propósito — responder de outro
endereço, com bytes que não são DNS, ou não responder. O que vai para ele
fica nele: não sai pela placa.

## O TLS (9.5)

O TLS também é **programa**: o pacote `tls` — o `rustls` sem `std`, com um
provedor de cifra próprio — roda dentro do processo, sobre a interface
nativa (`programas::tls`). O kernel não tem TLS: não depende do pacote, e o
`xtask` confere que não passa a depender.

Um certificado não autoriza nada, e o nome do servidor não é recurso:

- **O destino é decidido antes do primeiro byte do TLS.** `net.connect`
  com o destino inteiro, pelo gate, como qualquer conexão; fora do
  alcance, a recusa é do gate (`DENY_RESOURCE`), e o `ClientHello` nem é
  montado. O nome que o programa quer provar vai no aperto, e não passa
  pelo gate: o mesmo destino, decidido uma vez pela política, pode servir
  um nome que o programa aceita e outros que ele recusa — a bancada tem
  quatro.
- **Provar o nome é do programa, pelas âncoras dele.** A âncora é um
  arquivo que o programa lê por `fs.read`, pelo gate; a semente de cada
  conexão vem do `random.read`, e a hora da validade, do objeto `time` do
  `system.info` — o civil autenticado, ou o tempo lógico sem ele, e nunca o
  RTC cru —, os dois pelo gate. A verificação não tem atalho: o
  `xtask` confere que nenhum código chama a API `dangerous()` do `rustls`
  nem escreve um verificador próprio.
- **A sessão não autoriza o que vem depois do aperto.** Cada `net.send` e
  cada `net.recv` é decidido de novo: a política que tira o destino, o
  processo isolado e a regra do firewall valem no pedido seguinte, no meio
  da sessão cifrada.

As falhas não se misturam. A recusa do gate e a do firewall passam pelo
TLS com o código delas — `DENY_RESOURCE`, `DENY_CONTAINED`,
`FIREWALL_BLOCKED`, `RATE_LIMIT`, `NETWORK_UNAVAILABLE` —, sem virar um
código do TLS; as do TLS têm os seus — `TLS_UNTRUSTED`,
`TLS_NAME_MISMATCH`, `TLS_EXPIRED`, `TLS_NOT_YET_VALID`,
`TLS_HANDSHAKE_FAILED`, `TLS_TAMPERED`, `TLS_INTERRUPTED`; e as locais —
sem entropia, sem relógio, um pedido malformado — os seus
(`ENTROPY_UNAVAILABLE`, `CLOCK_UNAVAILABLE`, `INVALID_REQUEST`,
`TECHNICAL_ERROR`). Uma sessão que falhou fica quebrada com a falha que a
quebrou: o registro que não saiu já gastou o número dele, e a seguinte
mentiria.

O NSF vê do TLS o que vê de qualquer conexão: as decisões do gate — a
conexão, cada envio e cada leitura, com o destino —, e nada de dentro
(ver [limitações](#limitacoes-deliberadas)).

A bancada é o **OpenSSL**, pelo módulo `ssl` do Python do hospedeiro —
outra implementação inteira do protocolo —, que o emulador roda a cada
conexão a `10.0.2.100:443` (`xtask/src/tls.rs`). A PKI é gerada a cada
máquina, fora do repositório; a chave da raiz nem chega ao disco.

## O canal do agente por TCP (9.6)

O canal do agente ganhou um transporte: as sessões 5 a 8, uma por conexão
aceita na porta 7070. A conexão não traz autoridade, e o canal não tem
política própria: o aperto é o mesmo das portas (o IK do Noise, a chave no
registro), cada pedido passa pelo gate com o papel da chave, e a taxa, a
contenção, a revogação e a janela de apertos são as mesmas. O endereço do
par vai para a auditoria, ao lado da chave — como o que se sabe de por
onde veio —, e não entra em decisão nenhuma.

- **A chave só vale confirmada.** A primeira mensagem do IK pode ser
  repetida por quem a capturou; pela rede, a sessão de quem repete
  seguraria uma vaga, e diria que o dono da chave estava conectado. No
  TCP, o aperto só termina no primeiro quadro que abre: é só então que ele
  vai à auditoria como completo, que o agente conta como conectado e que a
  conexão é dele para o firewall. A sessão que acaba antes — o prazo de dez
  segundos, um quadro que não abre, a conexão que cai, a revogação — vai à
  auditoria como um aperto recusado, com a chave alegada e o par.
- **O firewall alcança o canal.** A conexão aceita é um fluxo da tabela,
  do agente que confirmou a chave: a regra que barra o par dela, para o
  agente dela, a derruba e encerra a sessão, gravada como execução do
  bloqueio em nome de quem pôs a regra. A escuta não protege ninguém.
- **O NSF observa pela auditoria.** Os apertos recusados pela rede — a
  chave fora do registro, a revogada, a suspensa, o quadro que não é um
  aperto, o prazo vencido — são registros `session.open` como os das
  portas, com o par no detalhe; as regras de credencial os leem como leem
  os outros. O NSF não pede nada ao gate por quem não se autenticou, e não
  há um sensor do TCP fora do gate.
- **A administração é a de sempre.** `admin.challenge` e `admin.execute`
  pela sessão TCP, com a prova amarrada ao número dela: o administrador
  recupera o sistema por qualquer canal, e por nenhum sem a prova.
- **O que a conexão leva quando cai, e o que não.** A sessão, as conexões
  de rede que o agente abriu por ela e os arrendamentos dele — gravados em
  nome dele —; quem conecta depois na mesma vaga, mesmo com a mesma chave,
  não herda nada. O processo que ele lançou pela rede age pela chave, e
  não pela conexão: continua o agente depois que ela cai, e perde a
  autoridade na hora em que a chave é revogada.

## O HTTP (Fase 12)

O HTTP/1.1 também é **programa**: o pacote `http` — o cliente, puro, sem
dependência nenhuma — roda dentro do processo, sobre a conexão do gate,
direto no TCP ou com o TLS no meio (`programas::http`), com o nome
resolvido pelo DNS do próprio programa. O kernel não tem HTTP: não depende
do pacote, nenhum comando do registro e nenhuma permissão da política é do
HTTP, e o `xtask` confere as três coisas.

Não há uma segunda política para o protocolo, nem autorização paralela:

- **O que o gate decide é o destino.** Cada conexão é um `net.connect`
  com o destino inteiro — o endereço que o DNS deu, decidido como se
  tivesse sido digitado —, e cada envio e cada leitura são decididos de
  novo, com a autoridade de quem lançou o processo — a pessoa pela sessão,
  o agente pela chave —, e gravados com ela. O método, o caminho, o
  `Host`, os cabeçalhos, o status, o corpo, o redirecionamento e o
  *keep-alive* não chegam ao gate: não viram permissão, recurso nem regra.
- **Nada no caminho autoriza.** O DNS dá um endereço, e o endereço fora do
  alcance é recusado como o número digitado. O TLS prova o nome ao
  programa, e a sessão cifrada não autoriza o que vem depois do aperto. A
  conexão mantida não leva autorização de um pedido ao seguinte: a
  política nova, a revogação, a contenção e o fim da sessão valem no
  próximo `net.send` ou `net.recv` — no meio de uma resposta, inclusive: a
  resposta que chega depois de a chave ser revogada não é entregue.
- **Um 3xx não é seguido sozinho.** Volta a quem chama com o `Location`;
  ir até lá é outro pedido — outro nome no DNS, outro destino no gate.
- **A compressão é do programa.** O pedido diz o que o cliente decodifica
  (`Accept-Encoding`), e o corpo em `gzip` ou `deflate` é decodificado no
  processo, pelo pacote `http`, com um teto que quem pede fixa antes de
  descomprimir — a bomba custa o teto, e para. O gate decide a conexão,
  cada envio e cada leitura pelos bytes que passam, comprimidos ou não, e
  nenhuma decisão depende do algoritmo: a mesma página como é e
  comprimida passa pelas mesmas decisões, e só o número de leituras muda.
  O kernel e a política não falam de codificação de conteúdo, e o `xtask`
  confere.
- **Os cookies são do programa, e não são credencial.** Um cookie é o
  estado que um servidor pede para o programa guardar e mandar de volta:
  prova alguma coisa ao servidor, e nada ao Duke. Ele vive num pote na
  memória do processo (`http::Pote`), com as regras da RFC 6265 e da
  6265bis — domínio, caminho, `Secure`, `HttpOnly`, `SameSite`, validade
  e tetos —, e não é identidade de ninguém: quem pede é o processo, com a
  autoridade de quem o lançou, e o registro diz essa pessoa ou esse
  agente, nunca um cookie. Um servidor não muda a autoridade de nada com
  um `Set-Cookie`: o pote é estado do programa, e o gate não o lê. A
  revogação, a contenção e o firewall valem no pedido seguinte, leve ele
  a sessão ou não — e, liberado, o processo segue com a sessão dele, que
  lá fora nunca deixou de valer para o servidor. Um processo não vê o
  pote de outro: a memória de cada um é dele, e a página que o kernel dá
  chega zerada; duas pessoas, ou uma pessoa e um agente, têm cada um o
  seu, e dois processos da mesma pessoa também. Nada se guarda além do
  processo. O relógio da validade é o `system.info`, pelo gate, uma vez
  por troca e só quando um cookie com validade está em jogo; sem ele, o
  que tem validade não vai — a resposta diz quantos ficaram. Essa leitura
  é do caminho de controle, e gasta a taxa de quem lançou o programa — a
  sessão da pessoa, ou a chave do agente: uma rajada de trocas com
  cookies de validade a esgota, e até ela voltar os de validade ficam no
  pote, e os outros pedidos de controle dos programas dele — o relógio de
  uma conexão TLS nova inclusive — ouvem `DENY_RATE`. A segurança não
  cede; cede a conversa. O kernel e a política não falam de cookie, e o
  `xtask` confere.
- **O HTTP/2 é do programa, e multiplexa pedidos, e não autoridade.** O
  cliente do pacote `http` fala HTTP/2 (RFC 9113, com o HPACK da RFC 7541)
  pelo TLS, quando o ALPN o escolhe, ou no claro, com conhecimento prévio.
  Várias correntes numa conexão são vários pedidos de um processo só: a
  conexão é um `net.connect` decidido pelo destino, cada envio e cada
  leitura dela são decididos de novo, com a autoridade de quem lançou o
  processo, e uma corrente não é uma conexão, um titular nem uma decisão —
  o gate não sabe que elas existem. A revogação, a contenção e o firewall
  no meio das correntes acabam com a conexão inteira, e cada corrente que
  esperava ouve o código como veio: nem um erro do HTTP/2 no lugar da
  recusa, nem metade de uma resposta. O servidor que reinicia ou recusa uma
  corrente falha só ela; o que quebra o protocolo — o *push* que o cliente
  desligou, o bloco de cabeça que não se decodifica, a enxurrada de
  quadros sem progresso, o `GOAWAY` com erro — acaba com a conexão, e isso
  é do programa e do servidor, não do gate. A memória de uma conexão tem
  teto: as correntes que ela guarda, a janela de cada uma, a cabeça antes
  e depois de decodificada; além dele, o programa ouve o código do limite.
  O kernel e a política não falam de HTTP/2 — nem do h2c, do ALPN, do
  HPACK ou dos quadros —, e o `xtask` confere.

As falhas não se misturam. Cada uma sobe com o código de quem falhou, e a
família dela (`http::categoria`) só o nomeia:

| Família | Códigos | Quem falhou |
|---|---|---|
| `denied` | `DENY_*` (menos o da contenção), `RATE_LIMIT` | o gate |
| `contained` | `DENY_CONTAINED` | o gate, pela contenção |
| `firewall` | `FIREWALL_BLOCKED` | o firewall, depois do gate |
| `dns` | `DNS_UNAVAILABLE`, `DNS_NAME_NOT_FOUND` | o DNS |
| `transport` | `NETWORK_UNAVAILABLE`, `RESOURCE_LIMIT`, `CONNECTION_REFUSED`, `CONNECTION_RESET` | a rede, o teto, o outro lado |
| `timeout` | `NETWORK_TIMEOUT` | o outro lado, que não respondeu no prazo |
| `tls` | `TLS_*` (menos o fecho) | o TLS |
| `closed` | `HTTP_CLOSED`, `TLS_INTERRUPTED`, `HTTP_CONNECTION_SPENT`, `HTTP_STREAM_RESET`, `HTTP_STREAM_REFUSED`, `HTTP_CONNECTION_ENDED` | a conversa que acabou antes da hora — no HTTP/2, a corrente que o servidor reiniciou ou recusou, ou a conexão que ele encerrou com erro |
| `protocol` | `HTTP_MALFORMED`, `HTTP_UNACCEPTED_ENCODING`, `HTTP_CORRUPT_CONTENT` | o servidor, que não falou HTTP/1.1 nem HTTP/2 — ou não escolheu o HTTP/2 que o programa exigiu —, mandou uma codificação que o pedido não aceitou, ou um comprimido que não se decodifica |
| `limit` | `HTTP_TOO_LARGE`, `HTTP_TOO_MANY_STREAMS`, `HTTP_TOO_MANY_FRAMES` | a resposta, maior que os limites de quem pediu — o corpo como veio, ou o decodificado —; no HTTP/2, as correntes que a conexão guarda, e os quadros sem progresso |
| `request` | `INVALID_REQUEST` | o pedido, que não se escreve |
| `local` | o resto | o programa |

Um código que nenhuma camada dá é `local`: nada que não se reconhece vira
recusa de alguém, nem permissão.

O NSF vê do HTTP o que vê de qualquer conexão: as decisões do gate — a
associação com o DNS, a conexão, cada envio e cada leitura, com o destino
— e o nome que o sensor do DNS ligou ao endereço (`security.explain`).
Nada do protocolo: não há regra do NSF sobre HTTP, nem leitura do que vai
dentro — e, no `https`, nem os bytes. O uso normal não abre incidente: a
suíte confere que a cadeia inteira não leva o NSF a pedir nada.

## O tempo (T7.3 a T7.5)

O relógio civil autenticado não dá ao NSF autoridade nenhuma sobre ele. O
serviço de hora é um principal como o NSF —
`Autoridade::Servico(Servico::Hora)`, o papel `tempo`, o balde dele —, e o
que o NSF faz com o tempo é ler:

- **O tempo vem dos registros, nunca de um relógio.** `seguranca::tempo`
  lê os registros de execução de `time.sync` — o veredito de cada
  resposta, com o código da classe: `ALLOW`, `DENY_CREDENTIAL` (a
  assinatura ou a delegação que a chave fixada não fecha), `DENY_REPLAY`
  (o nonce ou o pedido de outro), `INVALID_ARGUMENT` (a forma, o raio),
  `ERROR` (sem resposta, vencida) —, o desfecho de cada rodada (o civil e
  o lógico antes e depois, o estado, as marcas `pendente`, `divergente`,
  `adiantado`) e os `time.confirm` executados. O `security.status` diz o
  estado da última rodada, as marcas e as contagens.
- **As regras de tempo registram e recomendam** (T7.5): o salto, o salto
  além do envelope, o pendente, a fonte divergente, a assinatura que a
  chave fixada não fecha, a hora vencida ou nunca autenticada, o lógico
  parado — cada uma uma vez por acontecimento, com o relógio (`clock`) como
  principal. O NSF não ajusta o relógio, não confirma salto — recomenda o
  `time.confirm` da rodada a quem tem a prova —, não bloqueia fonte e não
  cria autorização emergencial; nenhuma regra de tempo é da categoria que
  sustenta contenção, e as invariantes conferem quem chama o que move o
  civil.
- **Com o lógico parado, a contenção por taxa fica suspensa.** O NSF sabe
  da parada pela marca `adiantado` no fechamento de uma rodada, ou pela
  confirmação que deixa o lógico à frente do civil, e da volta pelo
  primeiro carimbo maior. As detecções das regras de janela continuam
  registradas, marcadas, e abrem o incidente; a contenção que só uma janela
  sustenta vira recomendação, com o motivo, e a janela contada parada não a
  sustenta nem depois que o lógico volta a andar. O que não é janela
  contém parado ou não. O `security.status` diz `logical_stopped`,
  `stopped_at_ms` e `rate_containment`.
- **O serviço de hora é observado e nunca alvo.** Nenhuma regra nem perfil
  o conta, e nenhuma resposta do NSF chega a ele nem às fontes dele: quem
  injeta respostas ruins no caminho não faz o NSF cortar a fonte legítima.
- **Nenhuma decisão lê o tempo.** O gate decide pelo relógio do kernel; o
  estado do civil não concede nem nega nada. A validade dos certificados e
  a dos cookies é dos programas, pela hora do `system.info` (ver o README,
  *Os consumidores da hora*), e o cookie não é identidade, credencial,
  autoridade nem permissão.

## As consultas

Todas pelo gate, com a permissão `security.read` (sensível: diz o que os
outros fizeram):

| Comando | O que diz |
|---|---|
| `security.status` | o NSF: identidade, papel, o que leu, o que perdeu, incidentes |
| `security.incidents` | os incidentes; com `id`, um inteiro |
| `security.events` | a linha do tempo: de um ator, de um incidente, ou toda |
| `security.explain` | a interpretação de uma decisão gravada — nunca uma segunda decisão |
| `security.provenance` | a cadeia de um processo até a raiz, com a rede dele |
| `security.risk` | o risco e o perfil de um principal, com os motivos, e o raio de alcance do que ele já tocou |
| `security.verify` | refaz o cofre de evidências |
| `net.rules` | as regras do firewall e os descartes |

## O que não se mistura

| Conceito | Mora em | O NSF |
|---|---|---|
| Autorização | o gate | pede a ele, e é recusado por ele |
| Alcance de caminho e de destino | a decisão do gate | não alarga, não interpreta como permissão |
| Arrendamento | `coordenacao` | observa pela auditoria |
| Versão | o armazém, a árvore | observa pela auditoria |
| Persistência | o journal | não grava nada nele |
| Auditoria | a cadeia | lê pelo gate, refaz os elos, nunca escreve fora do funil |
| Segurança | o NSF | interpreta e pede |

## As decisões consolidadas

Nenhuma muda. O que o NSF acrescenta é extensão do que já existe, pela
mesma regra:

- o principal novo (`Autoridade::Servico`) decide pela mesma conta dos
  outros: papel da política, permissão, alcance, taxa, auditoria — como a
  pessoa entrou ao lado do agente;
- as três permissões novas entram no vocabulário fechado, como entraram
  `net.connect` e `message.*`, com alcance enumerado onde há recurso;
- o `sistema` ganha `security.read` e `net.block` **escritas na linha
  dele**, com o alcance enumerado — continua sem curinga;
- o DNS é o caminho 1 aprovado: programa sobre o UDP, sem `net.resolve`,
  sem nome na política;
- o TLS segue o mesmo caminho: programa sobre o TCP, sem TLS no kernel; o
  certificado prova o nome ao programa, e não autoriza nada no gate;
- o HTTP também: programa sobre o TCP ou o TLS, sem HTTP no kernel, sem
  comando nem permissão dele; o gate decide o destino, e o protocolo é do
  programa — a compressão do corpo inclusive, decodificada no processo,
  os cookies, num pote do processo que o gate não lê, e o HTTP/2, com o
  ALPN no TLS: as correntes numa conexão que o gate decidiu pelo destino;
- a conexão cortada pelo firewall guarda o número para o dono: a ordem
  continua a mesma — o gate decide, e o firewall barra depois —, e o que
  muda é só o código que o dono ouve, o do firewall;
- a revogação continua a do 4a1/L6: o NSF a recomenda, e quem tem a prova a
  executa.
- o tempo: o serviço de hora é outro serviço, com o balde dele, e o NSF só
  lê o que a auditoria conta dele — não move, não confirma, não corta
  fonte; as regras de tempo registram e recomendam, e o lógico parado
  suspende a contenção por taxa, sem suspender a detecção.

Um ponto pediu cuidado e ficou dentro da regra: **observar é acessar**. Um
gancho no funil da auditoria daria ao NSF a cadeia inteira sem permissão
nenhuma escrita — acesso por ser componente de segurança. Por isso a
observação é pelo gate, e o custo dela (um registro por leitura) é aceito e
contido pelo despertador.

## Limitações deliberadas

- **O estado do NSF é volátil.** Incidentes, perfis e o cofre moram na
  memória; o que sobrevive a um boot é a auditoria, de onde o NSF os
  refaz pela janela que o journal repõe. A captura e as regras do firewall
  não voltam.
- **As regras do firewall não vão ao journal.** Uma contenção é medida de
  incidente; depois de um boot, o gate continua decidindo tudo, e o NSF
  vê o incidente de novo, sem repetir a contenção sozinho.
- **Contenção só de rede.** Isolar um processo inteiro, encerrar um agente
  e revogar uma credencial são recomendações: comandos para isso dariam ao
  NSF uma autoridade que hoje só a prova de um administrador tem.
- **Captura só de UDP**, e só de destinos que um papel tem em
  `net.observe`.
- **Lê a cada segundo, no máximo.** A latência entre o evento e a
  contenção é a do despertador.
- **A taxa do papel vale para o NSF.** Uma volta lê até oito lotes de 64
  registros, e o papel `seguranca` tem dez pedidos por segundo, com rajada
  de vinte: sob uma carga que passe disso por muito tempo, a leitura fica
  para trás, uma recusa por taxa faz o NSF recuar (até um minuto), e o
  que sair do anel de 1024 registros antes da leitura vira a detecção da
  lacuna. O NSF não ganha taxa por ser de segurança. Com o plano de dados,
  uma transferência grande deixa de ser limitada pela taxa do papel, e a
  auditoria pode crescer mais depressa do que ele lê; a contrapressão do
  caminho da auditoria é a do journal, e não a dele — o gate não sabe que
  o NSF existe. O NSF que fica para trás se declara degradado
  (`audit-gap`); o que ele não leu está no journal, e não foi perdido.
- **O NSF não vê dentro do TLS.** Nem o nome pedido no aperto, nem a
  recusa do certificado: esses são do programa. Ele vê as decisões do
  gate sobre a conexão, como as de qualquer outra; um programa que
  insiste num servidor que não prova o nome aparece como conexões
  curtas e repetidas ao mesmo destino, e não como "certificado recusado".
- **O canal TCP nomeia o par inteiro.** Uma regra do `net.block` sobre
  uma conexão do canal nomeia o par com a porta efêmera dele — o alcance
  do `net.block` é enumerado, sem curinga —, e não barra a conexão
  seguinte do mesmo endereço. Para tirar um agente da rede, a revogação e
  a suspensão da credencial valem em qualquer conexão.
- **Os apertos pela rede gastam a janela da vaga.** A janela de apertos
  é por sessão, e uma enxurrada de conexões sem chave a esgota: os
  agentes de verdade esperam a janela, e cada um, o prazo de quem não fez
  o aperto. O canal limita quanto tempo e quantas vagas um estranho
  segura, e não que ele tente.
- **O NSF não interpreta HTTP.** Nem o método, nem o caminho, nem o
  status, nem a codificação do corpo, nem os cookies, nem as correntes do
  HTTP/2: só as decisões do gate sobre a conexão, e o nome que o DNS deu.
  Uma sessão roubada de um servidor é problema daquele servidor; aqui, ela
  não abre nada.
  Um programa que insiste num caminho que o servidor recusa aparece como
  pedidos `ALLOW` ao mesmo destino, e não como "404 repetido".
- **O relógio dos registros é de um segundo.** As janelas e as taxas das
  regras e do perfil contam com essa resolução; a ordem entre a captura e
  a auditoria é a dos números dos registros, que é exata.
- **O lógico parado junta as janelas, e só uma rodada o diz.** Depois de
  um salto do civil para trás, o lógico fica no piso, e os carimbos param
  com ele: as janelas das regras juntam o que no relógio de verdade está
  separado. Na bancada de tempo, um operador recusado em três métodos, um a
  cada 35 s, com o lógico parado: os três registros saem com o mesmo
  carimbo, e dão uma detecção e um incidente; a saída dele depois disso fica
  na recomendação, e o NSF não pede nada. A suspensão depende de um
  registro que mostre a parada — o fechamento de uma rodada, ou uma
  confirmação —: sem fontes no registro, ou antes da primeira rodada de um
  boot que sobe com o RTC atrás do piso, o NSF não sabe que o lógico está
  parado, e a janela conta como sempre.

## Como se confere

- **No hospedeiro** (`cargo test -p seguranca`): o modelo de evento, a
  cadeia, o grafo, o perfil, as regras, o incidente, o cofre, a resposta e
  o firewall puro; e o motor de ponta a ponta sobre uma auditoria escrita
  com os elos de verdade — da sondagem à contenção, a recusa que encerra o
  objetivo, a história que não pede, a ação sem plano, a adulteração e a
  lacuna, a proveniência, o DNS nas duas ordens, pessoa e agente pela
  mesma conta, e só o incidente alto levando à contenção; e as regras de
  tempo sobre uma rodada escrita como o kernel a escreve, a confirmação que
  para o lógico, a contenção por taxa suspensa com ele parado e com a
  janela contada parada, o contorno que contém parado, e a janela que volta
  a conter com ele andando.
- **Na suíte**, com o motor de verdade e sem o fio — cada volta é o caso
  que dá, e cada caso começa com o NSF sem história, sem espera e com o
  balde da taxa do papel cheio, porque as voltas vêm uma atrás da outra,
  sem a cadência do fio: o NSF lendo pelo gate com o papel dele, cego sem
  `audit.read` e sem papel sem a linha `servico`; o NSF não sendo o
  sistema; a contenção de um agente e de uma pessoa pelo mesmo caminho; a
  recusa que encerra o objetivo; a proveniência pelo `user.run` e pelo
  `fork`, com o nascimento antes do primeiro pedido do filho; a credencial
  revogada; o NSF num fio dele lendo junto com quatro fios que pedem — até
  ele dar três voltas com eles; a lacuna do anel; o firewall só
  restringindo, depois do gate; os quadros sem fluxo, o ICMP e o aviso da
  conexão derrubada; o `resolvedor` contra a bancada; e a resposta que não
  dá acesso — religada, forjada, muda, malformada, de um servidor fora do
  alcance.
- **Na fumaça**, o kernel de produção com o fio do NSF de verdade: a
  leitura pelo gate, a sondagem que abre o incidente sem ação, a saída
  contida pelo gate em poucos segundos, o firewall barrando só o operador,
  o incidente dizendo a decisão e quem autorizou, e a auditoria quieta
  depois — entre duas rodadas do serviço de hora, que escreve as dele.
- **Na bancada de tempo**, a imagem de produção com o fio do NSF, pela rede
  de verdade: a fonte divergente, o `adiantado` e o `vencido` no
  `security.status`; a sondagem lenta com o lógico parado, que vira
  detecção e incidente, e a saída depois dela, que fica na recomendação —
  parado, e depois andando, pela janela contada parada —; o lógico parado
  num boot com o RTC atrás do piso, e no RTC além dos certificados.

## Incrementos e estado

| | O que entra |
|---|---|
| NSF-0 | este desenho |
| NSF-1 | o pacote `seguranca`: evento, correlação, grafo, UEBA, risco, regras, invariantes, incidente, evidência, resposta, firewall puro — testados no hospedeiro |
| NSF-2 | o kernel: o serviço na política, o titular, a autoridade, o fio do NSF lendo pelo gate, as consultas, os registros novos de processo |
| NSF-3 | o firewall na pilha, `net.block`/`net.unblock`/`net.rules`, a resposta pelo gate |
| 9.4 | `protocolo::dns`, o resolvedor como programa, a captura e `net.observe`, a bancada determinística de DNS |
| NSF-4 | exercício: suíte, concorrência, contorno, revogação, proveniência, DNS, firewall, falhas; mutações; matriz; CI; relatório |
| 9.5 | o TLS como programa: o pacote `tls`, `random.read` e o `net.send` que espera espaço pelo gate, a bancada com o OpenSSL; a sessão interrompida pela política, pelo firewall e pela contenção |
| 9.6 | o canal do agente por TCP: as vagas, a escuta do firewall, a chave confirmada, a contrapressão; a revogação, a contenção, a regra e o administrador pela rede; o NSF lendo os apertos recusados |
| T7.3 | o relógio civil e o serviço de hora: o NSF lê o tempo nos registros de `time.sync` e `time.confirm` (`seguranca::tempo`, o `time` do `security.status`), sem regra nem resposta de tempo |
| T7.4 | a bancada de tempo: o Roughtime pela rede de verdade, e o NSF lendo dela as rodadas, as marcas e o estado — o divergente, o adiantado, o holdover, o vencido —, sem regra nem resposta de tempo; a sondagem lenta com o lógico parado, que vira detecção |
| T7.5 | os consumidores da hora: o TLS e os cookies pela hora do `system.info`, por uma regra só — o civil autenticado, o lógico sem ele, nunca o RTC cru —; as sete regras de tempo, que registram e recomendam; e a contenção por taxa suspensa com o lógico parado, com as detecções registradas |
