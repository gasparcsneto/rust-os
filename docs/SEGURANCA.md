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
| **Taxa** | um balde próprio, pela linha `taxa` do papel | `autorizacao::DonoDaTaxa::Servico` |

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
  conexão do mesmo protocolo (no TCP, com a quádrupla inteira), ou ao DHCP;
  o resto é descartado antes da pilha — sem RST, sem eco ICMP. O ARP passa.
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

A bancada da suíte tem um servidor de DNS determinístico, dentro da
máquina, num endereço que o emulador não tem (`10.0.2.53`): uma tabela que
o caso escreve, e modos para mentir de propósito — responder de outro
endereço, com bytes que não são DNS, ou não responder. O que vai para ele
fica nele: não sai pela placa.

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
- a revogação continua a do 4a1/L6: o NSF a recomenda, e quem tem a prova a
  executa.

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
  lacuna. O NSF não ganha taxa por ser de segurança.
- **O relógio dos registros é de um segundo.** As janelas e as taxas das
  regras e do perfil contam com essa resolução; a ordem entre a captura e
  a auditoria é a dos números dos registros, que é exata.

## Como se confere

- **No hospedeiro** (`cargo test -p seguranca`): o modelo de evento, a
  cadeia, o grafo, o perfil, as regras, o incidente, o cofre, a resposta e
  o firewall puro; e o motor de ponta a ponta sobre uma auditoria escrita
  com os elos de verdade — da sondagem à contenção, a recusa que encerra o
  objetivo, a história que não pede, a ação sem plano, a adulteração e a
  lacuna, a proveniência, o DNS nas duas ordens, pessoa e agente pela
  mesma conta, e só o incidente alto levando à contenção.
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
  depois.

## Incrementos e estado

| | O que entra |
|---|---|
| NSF-0 | este desenho |
| NSF-1 | o pacote `seguranca`: evento, correlação, grafo, UEBA, risco, regras, invariantes, incidente, evidência, resposta, firewall puro — testados no hospedeiro |
| NSF-2 | o kernel: o serviço na política, o titular, a autoridade, o fio do NSF lendo pelo gate, as consultas, os registros novos de processo |
| NSF-3 | o firewall na pilha, `net.block`/`net.unblock`/`net.rules`, a resposta pelo gate |
| 9.4 | `protocolo::dns`, o resolvedor como programa, a captura e `net.observe`, a bancada determinística de DNS |
| NSF-4 | exercício: suíte, concorrência, contorno, revogação, proveniência, DNS, firewall, falhas; mutações; matriz; CI; relatório |
