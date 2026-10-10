# Segurança sem fricção — o desenho

> A segurança é invisível quando tudo é normal, explícita quando algo é
> recusado, e decisiva quando há uma ameaça real.

Este documento é o desenho do incremento de usabilidade e operabilidade
da segurança. Ele **não** reabre nada do que está consolidado: identidade,
autoridade, política, gate, alcance, arrendamento, versão, persistência,
auditoria, proveniência, NSF, UEBA, risco, incidente, evidência, firewall,
DNS e resposta continuam como estão em `docs/INTERFACE.md`,
`docs/PERSISTENCIA.md`, `docs/ARMAZENAMENTO.md` e `docs/SEGURANCA.md`. O
gate continua o único ponto de decisão; nada aqui é uma segunda
autorização. O que muda é **o que acontece em volta da decisão**: como
uma recusa se explica, o que o NSF faz com o que é só incomum, quanto
custa a segurança, e como se volta de uma contenção.

## O que a inspeção achou

| Seção | Estado antes | O que este incremento faz |
|---|---|---|
| 1, 2, 4, 23 — nada reaberto; o normal invisível; anomalia não é autorização; firewall não é política | já valiam: o gate não lê o NSF (o `xtask` confere), e o firewall só restringe | conferido por mutação: "UEBA vira DENY", "NSF fora do ar bloqueia tudo" |
| 3 — incomum, risco, violação e contorno são coisas diferentes | as regras tinham só severidade | cada detecção ganha uma **categoria** e uma **confiança** |
| 5, 6, 7 — quatro níveis; o impacto pede confiança; a menor intervenção | a contenção automática era só `net.block`, decidida pela severidade do incidente | cada ação tem um **nível de impacto**, e o limiar de confiança cresce com ele; uma escada de contenções reversíveis, a menor primeiro |
| 8, 32 — o administrador contém e recupera sem o NSF | `net.unblock` existia; isolar processo, suspender agente e suspender credencial não existiam | as contenções reversíveis existem como comandos pelo gate e como operações administrativas com prova; o NSF respeita a recuperação |
| 9 — o NSF não é um gargalo | o gate nunca dependeu do NSF; o NSF não tinha estado de saúde | o NSF tem **saúde**: degradado, só age com confiança máxima; nunca bloqueia nada |
| 10 — o gate rápido | sem medida | a latência do gate medida em ciclos; o cache de decisões avaliado contra a medida |
| 11, 12 — granularidade e alcance | papéis com inclusão (`@observador`), alcance explícito, `policy.write` e `policy.assign` com prova | analisado; a expansão temporária de alcance por titular é uma decisão nova — ver o fim |
| 13 — o arrendamento não prende recursos | prazo de 1 s a 5 min, vencimento pelo coletor, invalidação no fim da sessão e na revogação | a suspensão de agente e de credencial também solta; um caso por evento |
| 14 — conflito de versão é `CONFLICT` | já era (`-32012`) | a explicação diz "o recurso mudou; leia de novo e repita" |
| 15–19, 33 — a taxonomia, a explicação para pessoas e para agentes, os laços de repetição, recusa não é erro técnico | o `data` do erro era o código, e o console escrevia só o código | toda recusa leva uma **explicação estruturada** e uma frase para pessoas; a recusa repetida não infla o risco |
| 20–22 — volume não é ameaça; agentes e pessoas legítimos são incomuns | a regra "fora do alcance" contava repetições, três falhas de login eram "abuso de credencial" alto, e dois pedidos barrados pelo firewall eram "contorno" alto | as regras contam o que distingue um ataque de uma repetição |
| 24 — o DNS não aumenta a fricção | a recusa do gate e a do firewall já eram diferentes | cada falha de rede tem um código: política, firewall, rede, DNS |
| 25–27 — auditoria, cofre e orçamento | o NSF já tinha tetos de memória e de trabalho por volta | os tetos ficam visíveis em `security.metrics`, com o custo medido |
| 28, 29 — sem cascata; contenção idempotente | "uma recusa encerra o objetivo" já existia | a contenção também encerra o objetivo; a mesma contenção não sai duas vezes |
| 30, 31 — recuperação; suspensão não é revogação | — | cada contenção tem o seu inverso; a revogação continua administrativa, com prova, gravada |
| 34–39 — métricas, testes e mutações de usabilidade | — | `security.metrics`; casos de uso, de falso positivo, de sobrecarga e de recuperação; as mutações da seção 39 |

## A recusa explicada

O gate devolve, numa recusa, o que ele decidiu: o código, a permissão, o
recurso, o papel e o número do registro da decisão na auditoria. Quem
responde a quem pediu transforma isso numa **explicação** — conta pura,
em `politica::explicacao`, testada no hospedeiro. A explicação **não é
uma segunda decisão**: ela só lê a que já foi tomada.

Para um agente, o erro JSON-RPC continua o mesmo — `code`, `message` e
`data` com o código da recusa, como sempre — e ganha um membro
`explain`:

```json
{"code":-32010,"message":"operacao negada pela politica","data":"DENY_RESOURCE",
 "explain":{"outcome":"DENY","reason":"DENY_SCOPE","code":"DENY_RESOURCE",
            "permission":"net.connect","resource":"tcp:10.0.2.99:7","role":"operador",
            "decision":1234,"recoverable":true,"retry":"requires_scope",
            "next_action":"REQUEST_SCOPE",
            "message":"net.connect sobre tcp:10.0.2.99:7 nao passou: o recurso nao existe para voce, ou esta fora do alcance do seu papel (operador). Confira o pedido; se ele estiver certo, um administrador pode incluir esse recurso no seu papel."}}
```

O `decision` é o número do registro da recusa na auditoria: quem lê a
auditoria — e o `security.explain` dele — vê o motivo exato, a regra e o
contexto (seção 16). Quem pediu vê o que a resposta pode dizer.

A taxonomia (`reason`) é a da recusa, e não a do código — dois códigos
antigos podem ter razões diferentes (uma chave revogada e uma porta sem
aperto são ambas `DENY_NOT_AUTHENTICATED`):

| `reason` | Quando | `retry` | `next_action` |
|---|---|---|---|
| `DENY_NOT_AUTHENTICATED` | ninguém provado: sem login, sem aperto, prova que não confere | `requires_user_action` | `LOGIN` |
| `DENY_REVOCATION` | a identidade foi revogada, ou a sessão acabou | `non_retryable` | `CONTACT_ADMIN` |
| `DENY_CREDENTIAL` | a credencial está suspensa | `requires_authorization` | `CONTACT_ADMIN` |
| `DENY_POLICY` | sem papel, o papel não tem a permissão, ou a política proíbe | `requires_authorization` | `REQUEST_AUTHORIZATION` |
| `DENY_SCOPE` | o papel tem a permissão, mas não sobre este recurso | `requires_scope` | `REQUEST_SCOPE` |
| `DENY_CONTAINED` | o processo está isolado, ou o agente suspenso | `requires_authorization` | `CONTACT_ADMIN` |
| `CONFLICT` | a versão mudou, ou outro titular tem o arrendamento | `retryable` | `REFRESH_AND_RETRY` ou `WAIT_AND_RETRY` |
| `LEASE_REQUIRED` | a ação pede o arrendamento, e quem pediu não o tem | `retryable` | `CLAIM_AND_RETRY` |
| `RATE_LIMIT` | passou da taxa do papel | `retryable`, com `retry_after_ms` | `WAIT_AND_RETRY` |
| `RESOURCE_LIMIT` | passaria de uma cota | `non_retryable` | `FREE_RESOURCES` |
| `INVALID_REQUEST` | o pedido não se entende | `non_retryable` | `FIX_REQUEST` |
| `REPLAY` | o pedido repete um que já passou | `non_retryable` | `FIX_REQUEST` |
| `TECHNICAL_ERROR` | permitido, e falhou ao executar | `retryable` | `RETRY` |

Para uma pessoa, o console escreve a frase da explicação, sem detalhe
que ela não tenha — o que ela pediu, o papel dela, e o que fazer —, e
logo abaixo o código e o número do registro: `negado: Seu papel
(observador) nao permite fs.read. ...` e `(DENY_PERMISSION; registro
1234)`. Uma recusa nunca é apresentada como erro técnico, nem um erro
técnico como recusa (seção 33): o `TECHNICAL_ERROR` diz "não conseguimos
agora", e não "você não pode".

### O que a explicação não distingue

O kernel responde **o mesmo** a um recurso que não existe, a um que é de
outro e a um fora do alcance — um destinatário revogado e um que nunca
existiu, a mensagem de outro e um número que ninguém tem, a conexão de
outro titular e uma que não há: todos `DENY_RESOURCE`, com a mesma
resposta, e o motivo exato só na auditoria. A explicação também: um
`DENY_RESOURCE` se explica igual, palavra por palavra, qualquer que seja
o motivo gravado — `DENY_SCOPE`, `requires_scope`, `REQUEST_SCOPE`, e a
frase "o recurso não existe para você, ou está fora do alcance do seu
papel; confira o pedido". Uma explicação que os distinguisse diria o que
o código calou: a primeira versão desta explicação dizia "corrija o
pedido" para o inexistente, e a suíte — os casos de vazamento das
mensagens — a pegou.

A explicação lê do motivo só o que é de quem pediu: a identidade dele
(revogada, ou sem aperto), o manifesto do programa dele, o arrendamento
que a resposta já mostra, e o pedido mal formado que ele mesmo escreveu.
A frase nunca carrega o motivo da auditoria — salvo a do pedido mal
formado.

Uma falha **depois** do gate — o firewall, a rede, o DNS — continua no
`result`, como sempre, e ganha um `code`: `FIREWALL_BLOCKED` (com a
regra), `NETWORK_UNAVAILABLE`, e, no programa de DNS,
`DNS_UNAVAILABLE`. "O gate recusou" e "o firewall barrou" nunca se
confundem (seção 24).

### A repetição

Um agente que repete o mesmo pedido recusado não pode transformar a
autorização em CPU, em registros nem em risco (seção 19). Três coisas:

- a explicação diz `retry`, e um `non_retryable` diz que repetir não
  adianta; um `RATE_LIMIT` diz quanto esperar;
- a taxa do papel já limita a repetição;
- as regras do NSF contam o que distingue uma ameaça de uma repetição: a
  sondagem conta métodos **distintos**, e "fora do alcance", recursos
  **distintos** — o mesmo pedido negado cem vezes é uma repetição, não
  um reconhecimento.

## A contenção reversível

Três contenções novas, cada uma com o seu inverso, todas pelo gate:

| Contenção | Inverso | Permissão | O que faz |
|---|---|---|---|
| `process.isolate {process}` | `process.release` | `process.isolate` | o processo continua existindo, mas todo pedido dele ao gate é `DENY_CONTAINED`, e as conexões dele caem |
| `agent.suspend {key}` | `agent.resume` | `agent.suspend` | o agente continua registrado e conectado, mas todo pedido dele, e dos processos dele, é `DENY_CONTAINED`; as conexões caem e os arrendamentos são soltos |
| `credential.suspend {person}` ou `{key}` | `credential.resume` | `credential.suspend` | a credencial não autentica — login e aperto recusados com `DENY_CREDENTIAL` —, e as sessões abertas com ela também não agem; os arrendamentos são soltos |

- **O recurso é o papel do alvo**, `papel:<nome>`, como o do
  `message.send`: cada papel enumera de quais papéis ele pode conter
  alguém. Sem curinga. O NSF, no papel `seguranca`, pode isolar processos
  de `observador` e `operador`, e nada mais; quem pode suspender agentes
  ou credenciais é o `sistema`, e o administrador com prova.
- **Idempotente**: conter o que já está contido responde `changed:false`
  (`already_isolated`), e nada muda; soltar o que não está contido,
  também.
- **Volátil**, como as regras do firewall: uma contenção é medida de
  incidente. Depois de um boot, o gate decide tudo de novo, e o NSF não
  repete uma contenção da história. O que é definitivo é a revogação —
  administrativa, com prova, gravada no journal. **Suspensão não é
  revogação**, e uma nunca vira a outra.
- **O administrador contém e recupera sem o NSF**: as seis operações
  também existem em `admin.execute`, com a prova de um administrador, e o
  papel `administrador` as enumera. O NSF nunca planeja uma recuperação,
  e quando vê, pela auditoria, alguém recuperar o que ele conteve, o
  objetivo daquela contenção acaba — ele não contém de novo só porque o
  risco ainda está alto (seção 32).

## O NSF: confiança, impacto e saúde

Cada detecção ganha:

- uma **categoria** — `unusual` (incomum: o perfil, o volume, uma cadeia
  de processos), `risky` (risco: DNS para destino recusado, falhas de
  autenticação, mudança de política recusada), `violation` (violação: o
  gate recusou por política — sondagem, fora do alcance, manifesto) e
  `bypass` (contorno de autoridade: o teto do administrador exercido, uma
  ação do NSF sem plano, a auditoria adulterada);
- uma **confiança** — baixa, média ou alta.

Cada ação de resposta tem um **nível de impacto**:

| Nível | Ações | Confiança exigida para o NSF agir sozinho |
|---|---|---|
| 0 — observar | registrar, atualizar o risco | nenhuma |
| 1 — alertar | incidente, recomendação | média |
| 2 — contenção reversível | `net.block` de um destino; depois, o dono: `process.isolate`, `agent.suspend`, `credential.suspend` | **alta**, a política autorizando, e o NSF saudável — ou degradado, e só para contorno |
| 3 — forte, definitiva | revogar credencial, encerrar agente | **nunca** sozinho: só recomendação a um administrador, que age com prova |

O nível 2 é uma escada, e não um degrau: primeiro o destino, só para o
dono do fluxo; o dono inteiro só quando ele já foi contido neste
incidente e a ameaça continuou. A política decide cada pedido: na padrão,
o papel `seguranca` tem `net.block` e `process.isolate` — sobre
`observador` e `operador` —, e não tem `agent.suspend` nem
`credential.suspend`. Pedidos esses, o gate os recusa, a recusa encerra o
objetivo (o NSF não procura outro caminho), e o incidente fica com a
recomendação para quem tem a autoridade.

A **escada** é a da seção 7: o NSF escolhe a menor ação que alcança o que
a detecção aponta, e só sobe um degrau quando a ameaça continua depois da
contenção — nunca porque a detecção é "grave" sem evidência. A confiança
alta exige corroboração: a sondagem sozinha é média; a sondagem **e** a
saída de rede depois dela são altas.

A **saúde** do NSF é `healthy` ou `degraded`, com os motivos: lacuna na
leitura, leitura recusada (a taxa, o papel), atraso grande, a história
sendo refeita. Degradado, o NSF continua observando e alertando, mas só
age sozinho com a confiança máxima (contorno, alta). O gate não sabe da
saúde do NSF — nem precisa: ele nunca dependeu dele.

## O custo da segurança

`security.metrics` (com `security.read`) diz o custo medido desde o boot
(`window_ms`). As medidas de tempo vêm do contador da arquitetura — o TSC
no x86, o `CNTVCT_EL0` no ARM —, convertido em nanossegundos pela razão
entre ele e o relógio do kernel desde o boot: a mesma conta nas duas
arquiteturas, sem conhecer a frequência. Cada medida é
`{samples, avg, max}`. Os contadores são atômicos, sem trava, e **nada
daqui volta a uma decisão**: o gate escreve, só a consulta lê.

| Membro | O que mede | Métrica da seção 34 |
|---|---|---|
| `gate.decisions`, `gate.denials`, `gate.denial_permille`, `gate.by_code` | as decisões do gate, as recusas e a proporção delas, por código | `security_block_rate` |
| `gate.latency_ns` | do pedido à decisão, sem o handler | `average_gate_latency` |
| `policy.latency_ns` | a conta da política sozinha | `average_policy_decision_latency` |
| `audit.latency_ns`, `audit.cpu_ppm` | montar e anexar um registro; a parte do tempo de máquina | `audit_overhead` |
| `nsf.round_ns`, `nsf.records_per_round`, `nsf.cpu_ppm` | uma volta do NSF, os registros que ela leu, a parte do tempo de máquina | `NSF_CPU_usage` |
| `nsf.engine.memory` | cada estrutura do motor contra o teto dela | `NSF_memory_usage` |
| `nsf.engine.false_positive_permille` | o incidente encerrado sem contenção e sem detecção de confiança alta | `false_positive_rate` |
| `nsf.engine.false_containment_permille` | a contenção do NSF que alguém, com a autoridade dele, desfez | `false_containment_rate` |
| `nsf.engine.agent_retry_permille` | a recusa repetida — mesmo titular, método e recurso | `agent_retry_rate` |
| `nsf.engine.legitimate_denial_permille` | a recusa de quem o NSF não tinha por ameaça | `legitimate_operation_denial_rate` |
| `response_latency_ms` | do registro que disparou a detecção ao pedido de resposta | `response_latency` |
| `leases.released`, `leases.expiry_delay_ms` | os arrendamentos soltos por vencimento, fim de sessão, revogação, suspensão e administrador; o vencido, quanto depois do prazo saiu | `lease_recovery_time` |

O tempo de máquina vai em partes por **milhão** (`cpu_ppm`), e não por
mil: o custo da auditoria e o do NSF ficam abaixo de um milésimo, e uma
medida que dissesse zero não diria nada.

### O gate sem cache (seção 10)

Medido na suíte (kernel de depuração, QEMU sem aceleração): uma decisão
do gate leva em média 2,1 ms; a conta da política — a única parte que um
cache de decisões pularia — 51 µs, uns 2,5% dela; o registro na
auditoria, que nenhum cache pula, 475 µs. Um cache teria de ser
invalidado por toda troca de política, de papel, de registro e de
contenção, e a mutação "um cache sem invalidação" mostra o preço de
esquecer uma: a política muda e o gate decide pela velha. **Sem cache.** Na fumaça — o kernel de produção, também de depuração —, com o fio
do NSF de verdade e muita atividade concentrada: 991 decisões, o gate
1,5 ms em média, a política 49 µs, um registro 649 µs; o NSF, 81 voltas
de 60 ms, cerca de 5% de um núcleo; a auditoria, 0,75%. A fumaça escreve
os números a cada rodada.

## Os casos

| Caso | O que confere |
|---|---|
| `recusa: diz por que e o que fazer` | o `explain` de cada recusa; o número é o registro, e o `security.explain` o interpreta; a mesma recusa repetida se explica igual |
| `recusa: a taxa diz quando repetir` | a recusa gasta a taxa; o `RATE_LIMIT` diz `retry_after_ms`, e esperado isso o pedido passa; a enxurrada não vira registro |
| `contencao: o processo isolado e solto` | um programa de verdade (`isolavel`) ouve `DENY_CONTAINED`, não bifurca, e solto pede; idempotência; a contenção some com o processo |
| `contencao: o agente suspenso e retomado pela prova` | arrendamentos soltos na hora; o administrador retoma pela porta do suspenso; suspender não é revogar, e a revogação apaga a suspensão |
| `contencao: a credencial suspensa nao entra` | login e aperto recusados com `DENY_CREDENTIAL` — e quem não tem a senha não sabe da suspensão |
| `usabilidade: o dia de trabalho com a seguranca ligada` | pessoa e agente trabalham — arquivos, versão, cópia, arrendamento, programa, mensagem, eco — com o NSF ligado: nenhuma recusa, nenhum incidente |
| `nsf: o incomum e observado, e nao contido` | a anomalia vira observação; a pessoa continua trabalhando depois de o NSF a ver |
| `nsf: a sobrecarga degrada sem bloquear` | a enxurrada degrada o NSF; degradado, ele só recomenda, e o gate decide como sempre |
| `seguranca: as metricas` | `security.metrics` fecha as contas e mede cada parte |

## Decisões novas — para quem decide

A seção 12 pede para investigar a expansão temporária de alcance
("delegação autorizada, lease temporário, expansão autorizada"). Hoje o
alcance é do **papel**, e o que muda o papel é `policy.write` e
`policy.assign`, com prova, para sempre (até a próxima mudança). Uma
expansão **temporária, por titular**, é um conceito que a política não
tem: uma entrada com prazo, que vale para uma identidade e não para um
papel, e que precisa vencer pelo tempo lógico e sobreviver a um boot.
Isso não se infere das invariantes — fica proposto, não implementado:
ver "Decisões pendentes" no README.
