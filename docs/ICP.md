# O Internet Computer (ICP-1)

O Duke consulta o Internet Computer (IC) de dentro de um programa: a
consulta (*query*) anônima a um canister, com a resposta **verificada**
contra a raiz da rede antes de ser entregue. É o primeiro incremento do
IC, e o único por enquanto — ver *O que não existe ainda*.

Nada disso é do kernel. O kernel não sabe o que é um canister, um
Principal, um método ou o Candid; a política não tem uma linha sobre o IC;
o gate decide o que sempre decidiu — se esta identidade, por este
processo, fala com este destino, agora. O IC é um protocolo de programa,
como o TLS e o HTTP.

## O caminho de uma consulta

```
programa icp ──► /dados/icp/redes ──► DNS ──► net.connect ──► TLS 1.3 ──► HTTP/1.1 ──► IC
   (fs.read, pelo gate)      (udp, pelo gate)   (pelo gate)    (âncoras do    (POST cbor)
                                                               programa)
```

1. **As redes.** O programa lê `/dados/icp/redes` por `fs.read` — o nome
   de cada rede, o endpoint HTTPS e a **chave da raiz** dela
   ([`web3::icp::registro`](../web3/src/icp/registro.rs)). A chave nunca
   se aprende da rede: um endpoint que mente não troca a raiz em que se
   confia.
2. **A conexão.** O host do endpoint pelo DNS do programa, ou o endereço
   fixo do arquivo; o destino pelo gate (`net.connect`), como qualquer
   outro: o alcance do papel, o manifesto, o firewall, a contenção; o TLS
   1.3 com as âncoras do programa; o HTTP/1.1 por cima — a conexão de
   [`programas::http`](../programas/src/http.rs).
3. **Os pedidos.** Um `POST application/cbor` para o `read_state` (o
   certificado da sub-rede do canister) e outro para o `query`. Cada
   `net.send` e cada `net.recv` são decididos de novo pelo gate: a
   revogação, a contenção e o firewall valem no meio de uma consulta.
4. **A verificação**, no processo ([`web3::icp`](../web3/src/icp.rs)):
   - o certificado da sub-rede: a delegação da raiz — de um nível só; uma
     aninhada é recusada —, a assinatura BLS de cada nível, o canister nas
     faixas da sub-rede, e o tempo do certificado a no máximo cinco
     minutos da hora de quem confere;
   - a resposta: a assinatura Ed25519 (ZIP215) de um nó **da sub-rede do
     certificado** sobre a resposta **deste pedido** — o id do pedido, com
     o nonce do `random.read`, entra no que o nó assina —, e o carimbo
     dela na mesma janela de tempo;
   - o Candid da resposta, lido com tetos: o truncado, o que sobra e o que
     não é Candid são recusados.

   A hora de conferir é a regra de `protocolo::usuario::hora`: o civil
   quando autenticado, o lógico quando não — a mesma das validades do TLS.
   Nada é entregue antes da verificação.
5. **A declaração.** O programa declara o desfecho à auditoria por
   `audit.declare`, ancorado na conexão em que a consulta foi — ver *A
   declaração*.

## Três coisas que não se confundem

| | O que prova | O que não é |
|---|---|---|
| o TLS | que o endpoint tem o nome pedido, pelas âncoras do programa | não é a resposta do IC, nem autorização |
| a verificação do IC | que os nós da sub-rede do canister responderam isto a este pedido | não é `ALLOW` do Duke |
| o gate do Duke | que esta identidade pode falar com este destino, agora | não diz nada sobre o canister |

E, pelas regras do ICP-1:

- **um Principal do IC nunca é identidade do Duke.** A consulta é anônima;
  quem pede ao gate é o processo, com a autoridade de quem o lançou;
- **um certificado TLS nunca é autorização**, e **um certificado do IC
  também não**: o que se prova não abre destino, papel nem recurso;
- **uma verificação nunca concede permissão.** Uma resposta verificada não
  muda nada que o gate decida depois — a suíte confere isso com a política
  que tira o gateway do alcance e com a que tira `audit.declare` do papel.

## O desfecho, numa palavra

O que o programa conclui de cada consulta
([`programas::icp::desfecho`](../programas/src/icp.rs)):

| desfecho | quando |
|---|---|
| `verified` | os nós responderam isto a este pedido |
| `verified_reject` | os nós provaram que o canister recusou — a recusa assinada também é verificada |
| `verified_malformed` | a prova fechou, e o Candid da resposta não se lê (o programa `icp`) |
| `unverified_certificate` | o certificado da sub-rede não vale: a raiz, a assinatura BLS, a delegação, as faixas, o tempo |
| `unverified_read_state` | a resposta do `read_state` fora da forma |
| `unverified_response` | a resposta da consulta não vale: sem assinatura, nó de fora da sub-rede, assinatura que não confere |
| `failed_connect` | a conexão: o DNS, o gate, o firewall, o TLS |
| `failed_transport` | a conversa caiu no meio: a recusa do gate, a contenção, o firewall, o par |
| `failed_http` | um status que não é 200 |
| `failed_request` | o pedido não se monta |
| `failed_clock` / `failed_entropy` | a hora ou o nonce, pelo gate |

`unverified` e `unverified_<motivo>` são a convenção que o NSF observa;
`failed_*` não são verificação que falhou — não houve o que verificar.

## A declaração

`audit.declare` é genérico (D1, variante C): um fato de aplicação que um
programa deixa na auditoria, como **alegação**. O programa `icp` declara

```
event   icp.query
subject <canister>/<método>          (só o canister, se o método não cabe na forma)
outcome <desfecho>
connection <número da conexão>       (opcional: a âncora)
```

e o kernel grava, no registro de execução da decisão do gate:

- no **recurso**, a alegação como veio — `icp.query
  pi33i-pt777-77776-aaaaa-cai/ola verified`;
- no **detalhe**, só o que o kernel sabe: o processo e o programa, a
  conexão e o **destino real** dela pela tabela da pilha — ou `sem
  conexao` —, e o número da decisão.

A decisão do gate é a de qualquer comando: a permissão `audit.declare` do
papel, atenuada pelo manifesto, **sem recurso** — nenhum campo da
declaração chega a ela. A declaração gasta a taxa de quem lançou o
programa, é recusada a um processo contido e a uma sessão que acabou, e
nenhuma decisão a lê: nem o gate, nem o firewall, nem as cotas, nem a
contenção. A âncora que não é do processo — de outro titular, ou que não
existe — é `INVALID_ARGUMENT`, e o programa declara de novo sem âncora: a
alegação fica, e o kernel diz que não havia conexão.

O NSF lê a declaração como alegação, ao lado da âncora do kernel, e
observa o desfecho `unverified*` com a regra `declared-verification-failed`
— confiança baixa, sem incidente, sem contenção, sem regra no firewall
(ver [SEGURANCA.md](SEGURANCA.md), *A declaração*).

## As bibliotecas

- **Reutilizadas direto**, `no_std` e conferidas nos dois alvos dos
  programas: `ic-verify-bls-signature` (e o `ic_bls12_381` que ela traz) —
  o emparelhamento BLS12-381 da DFINITY, sem reescrever. O SHA-256 dela,
  em software: o kernel não salva os registradores de SIMD de um processo.
- **Oráculos**, só nos testes do hospedeiro: `ic-transport-types`,
  `ic-certification`, `ic-certificate-verification`, `ic_principal`,
  `candid` e `ic-ed25519` — cada peça do `web3` conferida contra a
  oficial, nos dois sentidos. Nenhuma vai para um programa.
- **Referência**, lida e não dependência: o `ic-agent`, de onde vem a
  ordem da verificação. Portado, ele traria o `tokio`, o `reqwest`,
  sockets e DNS próprios e um repositório de raízes paralelo — tudo o que
  o caminho do Duke já é, por fora do gate.

## A bancada

`cargo xtask test` e `cargo xtask fumaca` sobem a bancada do IC
([`xtask/src/icp.rs`](../xtask/src/icp.rs)) antes da máquina:

- **a PocketIC 16.1.0**, o binário da release oficial da DFINITY, baixado
  uma vez para `target/pocketic/` e **conferido pelo SHA-256** antes de
  rodar. Ela escuta em `127.0.0.1`; nada de fora a alcança;
- **a instância**: a NNS e duas sub-redes de aplicação, com o canister da
  bancada na primeira — um módulo WebAssembly que o próprio script monta
  byte a byte ([`xtask/bancada/icp.py`](../xtask/bancada/icp.py)), sem
  toolchain: `ola`, `eco`, `recusa` e três métodos que respondem Candid
  fora da forma. A PocketIC deriva as chaves de sementes fixas: a raiz, o
  canister e a sub-rede são os mesmos a cada instância desta versão, e a
  bancada confere os três — uma PocketIC que mudou é um erro da bancada, e
  não um caso falhando sem dizer por quê;
- **o proxy**, sem porta no hospedeiro: um `guestfwd` do emulador roda, a
  cada conexão para `10.0.2.100:4943`, o script em modo `proxy` — o TLS
  1.3 com o certificado de `icp.duke` e `*.icp.duke` da raiz da bancada —,
  e o nome que o cliente pediu escolhe o que o proxy faz com a resposta:

| rede (nome no TLS) | o que o proxy faz | o que o programa tem de dizer |
|---|---|---|
| `bancada` (`icp.duke`, pelo DNS) | nada | `verified` |
| `lenta` | segura o `read_state` oito segundos | — (a suíte age no meio) |
| `raiz-errada` | nada; a chave do arquivo é a da rede principal | `unverified_certificate`: a delegação não confere com a raiz |
| `bls-invalida` | um bit trocado na assinatura do certificado | `unverified_certificate`: a assinatura BLS não confere |
| `sem-assinatura` | a resposta sem as assinaturas dos nós | `unverified_response` |
| `no-de-fora` | as assinaturas atribuídas a um nó de fora da sub-rede | `unverified_response` |
| `assinatura-errada` | um bit trocado na assinatura de cada nó | `unverified_response` |
| `pedido-trocado` | o nonce trocado no caminho: os nós assinam outro pedido | `unverified_response` |
| `aninhada` | uma delegação dentro da delegação | `unverified_certificate` |
| `faixa-errada` | o certificado de um canister da outra sub-rede | `unverified_certificate`: o canister não está nas faixas |
| `velho` | o `read_state` de quinze minutos atrás, guardado | `unverified_certificate`: certificado velho |
| `direta` (o endereço fixo, sem DNS) | nada | `verified` — a rede da fumaça, na imagem de produção, que não tem o DNS da suíte |

O gate decide um destino só, `tcp:10.0.2.100:4943`, para as doze: os nomes
são do TLS e do programa, e não autorizam nada.

## Os casos

Na suíte do kernel (`icp:`), com o programa
[`icp`](../programas/src/bin/icp.rs) lançado por uma pessoa operadora:

- **a consulta verificada pelo gate** — as seis respostas da bancada
  verificadas (o texto, o eco, a recusa, o Candid fora da forma recusado
  na leitura); uma conexão por consulta, decidida em nome da pessoa, pelo
  processo, para o gateway; a semente e a hora de cada consulta e do TLS,
  as âncoras e as redes lidas uma vez; cada passo declarado com a âncora
  do kernel; o Principal que não se lê não sai do processo; e nada do IC
  em registro nenhum fora da alegação;
- **cada prova adulterada é recusada** — as nove mentiras da tabela, cada
  uma com o motivo dela; o gate decidiu cada conexão como as honestas; o
  NSF observa as verificações declaradas que falharam, com confiança
  baixa, e só observa;
- **a revogação no meio da consulta** — a política que tira o gateway do
  alcance enquanto o programa espera a resposta lenta: a leitura acordada
  é `DENY_RESOURCE`, nada se entrega, o fecho é recusado e o kernel
  recolhe a conexão quando o processo sai; com a política de volta, a
  mesma consulta lenta verifica; a sessão da pessoa que acaba no meio:
  `DENY_NOT_AUTHENTICATED` na leitura **e** na declaração;
- **a contenção no meio da consulta** — a conexão cai na hora, a leitura é
  `DENY_CONTAINED`, a declaração também, e nem a hora de uma consulta
  nova; solto pelo sistema, verifica;
- **o firewall no meio da consulta** — `FIREWALL_BLOCKED`, gravado como
  execução da decisão `ALLOW` da leitura; a declaração ancorada no número
  cortado; a conexão nova barrada; sem a regra, verifica;
- **o alcance e a permissão são do gate** — sem o gateway no alcance,
  `DENY_RESOURCE` e nada enviado; sem `audit.declare`, a consulta verifica
  do mesmo jeito e a declaração é `DENY_PERMISSION`;
- **duas consultas ao mesmo tempo** — enquanto um processo dorme esperando
  a resposta lenta, o de outra pessoa consulta e verifica; cada
  declaração ancorada na conexão do seu processo.

No hospedeiro, `cargo test -p web3` confere cada peça contra os oráculos
— e o agente contra um IC de mentira, com os mesmos modos adversários.

## O que não existe ainda

De propósito, e cada um é uma decisão nova quando vier: a chamada de
atualização (*update*); identidade do IC com chave, e o armazenamento e o
ciclo de vida de chaves; *cycles*; implantar canisters; o `icp-cli` dentro
do Duke; o CDK; a EVM; o HTTP/3. Nem mudança no DNS, no TCP, no TLS, no
HTTP ou no gate: o ICP-1 roda sobre a infraestrutura que já existia.
