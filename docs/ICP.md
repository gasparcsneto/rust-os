# O Internet Computer (ICP-1, ICP-3 e ICP-4a)

O Duke fala com o Internet Computer (IC) de dentro de um programa: a
consulta (*query*) anônima a um canister — o ICP-1 —, e a chamada de
atualização (*update*), do anônimo ou assinada pela chave de uma
identidade do Duke — o ICP-3, em [A chamada assinada](#a-chamada-assinada-icp-3).
Nos dois, a resposta é **verificada** contra a raiz da rede antes de ser
entregue. O ICP-4a dá ao TLS do programa as cadeias das autoridades
públicas, que a rede principal usa — em [O TLS público](#o-tls-público-icp-4a).
O que ainda não existe está em *O que não existe ainda*.

Nada do IC é do kernel. O kernel não sabe o que é um canister, um
Principal, um método, o Candid ou o id de um pedido, e a política não tem
uma palavra do IC: o gateway da bancada é um destino do alcance, como os
outros, e a chave com que um programa assina é uma chave de assinatura
genérica — `chave:<nome>`, num domínio do registro de domínios da imagem
—, que o kernel guarda para a identidade dona dela e usa sobre um resumo
de 32 bytes, sem saber o que ele resume. O gate decide o que sempre
decidiu — se esta identidade, por este processo, fala com este destino,
ou assina com esta chave, agora. O IC é um protocolo de programa, como o
TLS e o HTTP.

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

`cargo xtask test`, `cargo xtask fumaca` e, no ARM, `cargo xtask iniciador`
— que roda a suíte inteira pela UEFI — sobem a bancada do IC
([`xtask/src/icp.rs`](../xtask/src/icp.rs)) antes da máquina:

- **a PocketIC 16.1.0**, o binário da release oficial da DFINITY, baixado
  uma vez para `target/pocketic/` e **conferido pelo SHA-256** antes de
  rodar. Ela escuta em `127.0.0.1`; nada de fora a alcança;
- **a instância**: a NNS e duas sub-redes de aplicação, com o canister da
  bancada na primeira — um módulo WebAssembly que o próprio script monta
  byte a byte ([`xtask/bancada/icp.py`](../xtask/bancada/icp.py)), sem
  toolchain: `ola`, `eco`, `recusa` e três métodos que respondem Candid
  fora da forma — e, desde o ICP-3, as atualizações `quem`, `contar` e
  `lento`. A PocketIC deriva as chaves de sementes fixas: a raiz, o
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

O gate decide um destino só, `tcp:10.0.2.100:4943`, para as doze — e para a
`assincrona`, a décima terceira, do ICP-3: os nomes são do TLS e do
programa, e não autorizam nada.

## Os casos

Na suíte do kernel (`icp:`), com o programa
[`icp`](../programas/src/bin/icp.rs) lançado por uma pessoa operadora:

- **a consulta verificada pelo gate** — as seis respostas da bancada
  verificadas (o texto, o eco, a recusa, o Candid fora da forma recusado
  na leitura); uma conexão por consulta, decidida em nome da pessoa, pelo
  processo, para o gateway; a semente e a hora de cada consulta e do TLS,
  as âncoras e as redes lidas uma vez; cada passo declarado com a âncora
  do kernel; os dois canisters que não são Principal — o texto fora da
  base32 e o da bancada com um caractere trocado, que só a soma recusa —
  não saem do processo, cada um com o seu motivo; e nada do IC em
  registro nenhum fora da alegação;
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

## A fumaça

Na imagem de produção, com a política padrão (`cargo xtask fumaca`, a sonda
*o IC, pelo operador*), o agente da porta 2, do papel `operador`, lança o
[`verificado`](../programas/src/bin/verificado.rs):

- o `ola` e o `eco` (`duke`) verificados pela rede `direta` — o endereço
  fixo, porque a imagem de produção não tem o DNS da suíte;
- o `ola` pela `bls-invalida`: `unverified_certificate`, nada entregue;
- cinco consultas `ola` seguidas, cada uma numa conexão nova, medidas por
  parte — a conexão (o TCP e o aperto do TLS), os dois pedidos, e o resto,
  que é a verificação, com a hora e o nonce pelo gate.

Cada consulta é declarada, ancorada na conexão dela, antes do fecho. Do
lado de fora, a fumaça lê a auditoria desde antes do lançamento, de 128 em
128 registros:

- as oito declarações — `icp.query pi33i-pt777-77776-aaaaa-cai/<método>
  <desfecho>`, na ordem das consultas —, cada uma com a âncora do kernel:
  `conexao N tcp:10.0.2.100:4943` e a decisão;
- as decisões do processo, todas `ALLOW` e só do que a consulta pede —
  `net.connect`, `net.send`, `net.recv`, `net.close`, `random.read`,
  `system.info`, `system.uptime`, `fs.read` e `audit.declare` —, com oito
  conexões para oito consultas;
- nada do IC — `pi33i`, `icp.query`, `icp.duke`, `read_state`, `/api/v3/`
  — em registro nenhum fora das declarações, de ninguém;
- nenhuma recusa por taxa e nenhum registro perdido.

## As medidas

Na imagem de produção, a mediana das cinco consultas do `verificado`, em ms
(o emulador sem aceleração, quatro núcleos):

| kernel de produção | x86 | ARM |
|---|---|---|
| depuração | conexão 120, pedidos 100, verificação 130 — **430** (340 a 610) | conexão 210, pedidos 100, verificação 110 — **380** (340 a 620) |
| release | conexão 90, pedidos 70, verificação 80 — **260** (220 a 440) | conexão 80, pedidos 70, verificação 90 — **230** (220 a 240) |

O programa é sempre o mesmo, compilado com otimização; o que muda entre as
linhas é o kernel. Rodadas diferentes variam: a mediana do x86 em depuração
deu 360, 420 e 430 ms em três fumaças.

No hospedeiro, nativo (`cargo test -p web3 --release -- --ignored
--nocapture medida`): a mesma leitura e verificação, sobre as respostas
gravadas de uma consulta ao IC de mentira — o certificado com a delegação
(duas assinaturas BLS), duas assinaturas de nó e o Candid —, em **5,5 ms**
de mediana (5,0 a 9,2 ms em 50). A verificação no emulador, de 80 a 130 ms,
é o mesmo código traduzido instrução a instrução.

Na suíte (o kernel de teste, o x86 em depuração), do pedido do `read_state`
à linha do desfecho — sem a conexão, com a declaração —, uma consulta
verificada leva de 660 a 810 ms (mediana 730); a prova recusada no
certificado, de 290 a 490 ms, porque a consulta nem sai.

## As mutações

Uma de cada vez, com o que a pega: os testes do hospedeiro (`cargo test -p
web3`), quando a mutação é do `web3`, e a suíte do x86 só com os casos
`icp:`, sempre. As dezessete morrem nas duas:

| mutação | onde | o que a suíte viu |
|---|---|---|
| a assinatura BLS do certificado não é conferida | `certificado.rs` | a `bls-invalida` verificou |
| a delegação não é conferida contra a raiz do arquivo | `certificado.rs` | a `raiz-errada` verificou |
| a delegação aninhada é aceita | `certificado.rs` | a `aninhada` verificou |
| as faixas da sub-rede delegada não são conferidas | `certificado.rs` | a `faixa-errada` caiu na conferência seguinte, com o motivo errado |
| o certificado velho é aceito | `certificado.rs` | a `velho` verificou |
| a assinatura do nó não é conferida | `consulta.rs` | a `assinatura-errada` verificou |
| o nó de fora da sub-rede é pulado, e não recusado | `consulta.rs` | a `no-de-fora` verificou |
| a resposta sem assinatura é aceita | `consulta.rs` | a `sem-assinatura` verificou |
| o Candid com bytes depois dos valores é aceito | `candid.rs` | o `candid_sobra` foi lido |
| o Candid sem a mágica é aceito | `candid.rs` | o `candid_magica` foi lido |
| o Candid truncado é lido até onde der | `candid.rs` | o `candid_truncado` entregou `ab` |
| o programa lê a falha do certificado como verificada | `programas::icp` | a `raiz-errada` declarada `verified` |
| o programa declara sem a âncora | `programas::icp` | seis casos: a declaração sem o destino do kernel |
| a contenção não alcança a declaração | kernel | contido, o `icp` declarou |
| o programa não pede o nonce ao gate | `programas::icp` | um `random.read` a menos por consulta |
| o Principal com o CRC32 errado passa da soma | `principal.rs` | o segundo canister recusado pela forma, e não pela soma |
| o Principal fora da soma e da forma é aceito | `principal.rs` | o segundo canister aceito |

As duas últimas passavam pela suíte na primeira rodada: o texto do passo do
Principal inválido era recusado pela base32, antes da soma e da forma. O
passo ganhou o canister da bancada com o vigésimo caractere trocado — um bit
dos bytes, e não do CRC nem da sobra da base32 —, que só a soma recusa, e a
suíte passou a conferir o motivo de cada recusa.

## A chamada assinada (ICP-3)

O ICP-3 dá ao programa a chamada de atualização, e a uma identidade do
Duke — uma pessoa, um agente — uma chave com que assinar. A cadeia
inteira, sem uma segunda autoridade em lugar nenhum:

```
pessoa / agente ─► identidade do Duke ─► sessão ─► processo ─► manifesto + papel
  ─► gate ─► chave:<nome> ─► reconfirmação ─► auditoria (e journal) ─► assinatura
  ─► programa icp ─► Principal do IC ─► chamada ─► certificado verificado
  ─► audit.declare ─► NSF
```

Até a assinatura, tudo é do Duke e genérico: uma chave, um dono, um
domínio, um resumo. Dali em diante, tudo é do programa: a pública vira o
Principal, o resumo é o id do pedido, e a resposta é conferida pela
verificação do ICP-1, sem mudar a arquitetura dela.

### A chave é da identidade

- **Ed25519 em software**, custódia `kernel`: a privada nasce do gerador
  do kernel e não sai dele. O campo `custody` existe para a custódia
  `tpm` que vier; não há código de TPM para chaves.
- **O dono é a identidade durável** — `pessoa:<id>`, `agente:<hex>`,
  `servico:<nome>` —, nunca a sessão, o processo ou a credencial: a pessoa
  que troca a senha, ou abre outra sessão, continua com as chaves dela.
  Pessoa e agente seguem o mesmo caminho: o dono é o que
  `autorizacao::dono_duravel` diz, e nada em `chaves.rs` pergunta qual dos
  dois ele é.
- **O nome é do dono.** O recurso `chave:<nome>` se resolve sempre no
  espaço de quem pede, e não há parâmetro de dono: o nome da chave de
  outro responde o mesmo que um nome que ninguém tem. A política enumera
  os nomes — `chave:*` é recusada.
- **Nada sai.** Nenhum comando devolve a privada, nem a recebe: não há
  exportação nem importação. A privada não aparece em resposta, erro,
  auditoria ou log — a suíte procura a semente em todos.
- **Sem chave do sistema.** O sistema não tem nenhuma permissão de chave,
  e a política de emergência também não; uma identidade do sistema com
  chave terá de ser enumerada pela política.
- **Limites:** 8 vivas por identidade, 64 vivas ao todo e 1024 entradas
  com as lápides; com a tabela cheia, nada se cria — o nome de uma lápide
  esquecida poderia voltar.

### Os comandos

| Comando | O que faz |
|---|---|
| `key.create` | Cria `chave:<nome>` no espaço de quem pede, num domínio que o papel usa; grava a semente no journal antes de responder |
| `key.read` | O que é público: a pública, a impressão, o algoritmo, o domínio, a custódia e o estado |
| `key.sign` | Assina um resumo de exatamente 32 bytes no domínio da chave |
| `key.destroy` | Destrói a chave de quem pede: a privada some, e o nome fica marcado para sempre |
| `key.revoke` | Só em `admin.execute`, com prova: anula a chave de outra identidade, e não dá o uso dela a ninguém |

O administrador anula; não assina com a chave de outro, não a assume, não
a muda de dono e não a exporta — nenhum comando de chave tem dono no
pedido, e o papel do administrador é um teto, que não se exerce. Ver o
README, *A política*, para os parâmetros.

### A assinatura, passo a passo

1. **O gate**: a identidade, a sessão, o papel, a permissão `key.sign`, o
   recurso `chave:<nome>` enumerado, o manifesto do programa, a contenção
   e a taxa. Uma decisão por assinatura.
2. **O pedido**: o nome no espaço de quem pede; o resumo com exatamente
   32 bytes, em 64 dígitos hexadecimais minúsculos — uma grafia só.
3. **O commit**, com a ordem das gravações na mão: tudo de novo — a
   autoridade, a sessão, o manifesto, a contenção (a reconfirmação passou
   a conferir a contenção também), o papel e o recurso —, a persistência
   disponível, o papel que usa o domínio, a chave viva e do domínio.
4. **A auditoria**: o registro da execução — a chave, o domínio, o resumo
   e a impressão, nunca a privada nem a assinatura — vai para a auditoria
   e para o journal. Sem o journal, nada se assina.
5. **A assinatura**: Ed25519 sobre o prefixo do domínio seguido do
   resumo, e nada mais.
6. **A resposta**: a assinatura, a pública, o registro e a decisão.

Uma revogação, uma destruição, uma contenção ou uma política nova gravam
com a mesma ordem: ou a assinatura as vê e é recusada, ou elas vêm depois
dela inteira. O registro correlaciona a identidade, a sessão, o papel, o
processo, o programa, a chave, o domínio, o algoritmo e a impressão com o
resumo assinado.

### O domínio

O registro de domínios da imagem (`/etc/duke/dominios`, ver
`sigilo::chaves`) dá a cada nome os bytes do prefixo; o xtask o escreve
com o nome e o separador que o `web3` usa, e só há um: `ic-request`, o
separador de domínio do pedido do IC. Quem assina diz o nome, nunca os
bytes; o domínio fora do registro é `INVALID_ARGUMENT`, e o do registro
que o papel não usa, `DENY_POLICY`. A linha `dominios <papel> <dominio>...`
da política diz que papéis usam que domínios. Não há domínio de
delegação.

### O que o kernel sabe

A chave, o dono, o algoritmo, o domínio registrado, o estado, o resumo de
32 bytes e a assinatura. Não sabe o Principal, o canister, o método, o
Candid, o id do pedido como conceito do IC, o endpoint nem o protocolo: o
xtask confere que o kernel e a política não têm uma palavra do IC. A
derivação pública → DER → Principal fica no `web3`.

### A chamada de atualização

No programa — [`web3::icp::atualizacao`](../web3/src/icp/atualizacao.rs)
e [`programas::icp`](../programas/src/icp.rs) —, a lógica do *update* do
`ic-agent`, síncrona e sem rede própria, em três pedidos:

1. **as faixas**: o `read_state` de `["subnet"]`, do anônimo — o
   certificado que prova de que sub-rede o canister é, até a raiz. Para
   um canister da sub-rede raiz, o certificado da chamada não traz
   delegação nem faixas, e elas só vêm desta leitura;
2. **a chamada**: `POST /api/v4/canister/<canister>/call`, com o envelope.
   Assinada, o remetente é o Principal auto-autenticado da pública — lida
   por `key.read` —, e a assinatura do id do pedido sai de um `key.sign`
   no domínio `ic-request`; do anônimo, nada disso. HTTP 200 traz o
   certificado do desfecho, ou a recusa que não passou pelo consenso;
   HTTP 202, nada ainda;
3. **a situação**, enquanto pendente: o `read_state` de
   `["request_status", <id>]`, **cada leitura outro pedido, assinado de
   novo** — outra decisão do gate —, até vinte vezes, com uma espera de
   500 ms entre elas que também é do gate: um `net.recv` da própria
   conexão que não lê nada. `received` e `processing` continuam
   esperando; `replied`, `rejected` e `done` acabam. A leitura vai sem
   nonce — como a do `ic-agent`, que nem tem o campo —, e a hora do
   programa conta em segundos; por isso a validade de cada leitura vai
   além da da anterior, um nanossegundo se a hora não andou, e duas
   leituras no mesmo segundo são dois pedidos, e duas assinaturas.

Cada certificado — o do corpo da chamada e o de cada leitura — é
conferido na sub-rede que o primeiro passo provou, e só então a situação
dele é lida. A recusa sem consenso (`non_replicated_rejection`) não é
verificação nenhuma: é dita à parte.

### O desfecho da chamada

| desfecho | quando |
|---|---|
| `verified` | o certificado provou a resposta |
| `verified_reject` | o certificado provou que o canister recusou |
| `verified_done` | o certificado provou que a chamada acabou, e a resposta já saiu do estado |
| `uncertified_reject` | a recusa antes do consenso, sem prova nenhuma — não é verificação que falhou |
| `pending` | nada provado depois das leituras |
| `unverified_certificate` | o certificado não vale: o das faixas, o da chamada ou o de uma leitura |
| `unverified_request_status` | a situação fora da forma no certificado |
| `unverified_read_state` / `unverified_response` | a resposta do `read_state` ou da chamada fora da forma |
| `failed_signature` | o kernel recusou uma assinatura — a chave anulada no meio, por exemplo |
| `failed_key` | sem a chave: o gate recusou o `key.read`, não há, está morta, ou é de outro domínio — e a chamada nem sai |
| `failed_connect`, `failed_transport`, `failed_http`, `failed_request`, `failed_clock`, `failed_entropy` | como na consulta; a espera recusada entre duas leituras é `failed_transport` da leitura, com o código de quem recusou |

### A declaração ancorada na assinatura

`audit.declare` ganhou uma âncora genérica, `decision`: uma decisão `ALLOW`
do mesmo processo de quem declara. O programa `icp` declara

```
event   icp.update
subject <canister>/<método>
outcome <desfecho>
decision <a decisão da assinatura da chamada>   (do anônimo: connection)
```

e o kernel escreve, no detalhe, `ancorada em <decisão> <método>`. A
decisão de outro processo, de outra identidade, recusada, de outra
declaração, que não está no anel, ou as duas âncoras juntas são
`INVALID_ARGUMENT`. A declaração continua alegação — nenhuma decisão a
lê —, e a decisão do gate continua o fato: não há `icp.audit`.

O NSF lê a âncora da decisão, liga a declaração à decisão no grafo
causal e a diz na proveniência (`"anchor":{"decision":N,"method":"key.sign"}`);
a verificação declarada que falhou explica a âncora — `pela decisao N
(key.sign)`. E a regra nova `dead-key-used` observa a assinatura pedida
com uma chave destruída ou anulada, que o kernel recusou: baixa na
primeira — a corrida de quem assinava quando a chave morreu —, média na
terceira da janela; só observa (ver [SEGURANCA.md](SEGURANCA.md)).

### O journal das chaves

A etapa A guardava as chaves só em memória; a etapa B as pôs no journal
de estado que já existia — o mesmo registro cifrado, a mesma âncora do
TPM, a mesma compactação, sem um segundo armazenamento:

- `key.create` grava a semente (`CHAVE_CRIADA`) com a decisão, no mesmo
  registro, antes de responder; sem persistência nenhuma chave nasce, e a
  gravação que falha desfaz a criação sem lápide;
- `key.destroy`, `key.revoke` e a revogação do dono gravam a lápide
  (`CHAVE_MORTA`, sem a semente); na operação administrativa, a lápide
  vai antes da revogação, no mesmo registro;
- a compactação leva a viva com a semente e a morta só como lápide;
- uma fotografia velha do disco é recusada pela âncora, e com o journal
  recusado nenhuma credencial entra: a chave destruída não assina por
  ela.

Ver [PERSISTENCIA.md](PERSISTENCIA.md), *As chaves de assinatura*.

### A bancada, de novo

- o canister ganhou três atualizações: `quem` responde o Principal de
  quem chamou, `contar` soma um ao contador dele — o estado muda — e
  `lento` roda trezentos milhões de voltas de um laço antes de responder;
- o mesmo módulo foi para um canister da NNS, a sub-rede raiz
  (`xp3jw-ot777-77777-aaaaa-cai`), que a bancada confere como os outros;
- a rede `assincrona`: o proxy responde 202 à chamada na hora, e só a
  entrega à PocketIC (pela via assíncrona, `/api/v2`) 1,5 s depois — as
  primeiras leituras acham a situação desconhecida;
- a `sem-assinatura` tira o certificado da resposta da chamada, e a
  `assinatura-errada` troca um byte da assinatura dele.

O arquivo das redes passou de 4 KiB com as treze, e se lê em duas
leituras — duas decisões do gate.

### Os casos

Na suíte do kernel, as chaves (`chaves:`), sem o IC:

- o caminho inteiro — criar, ler, assinar, destruir — pelo gate e pela
  auditoria, com a assinatura conferida na pública, no domínio e só nele,
  e a semente procurada na auditoria, no log e em cada resposta;
- o nome é do dono: duas pessoas e um agente com o mesmo nome têm três
  chaves, e a assinatura de uma não confere com a pública de outra;
- o alcance, o domínio, o resumo e o limite; o papel sem permissão, nas
  cinco operações; o sistema, que não alcança a chave de uma pessoa;
- a revogação do dono, o agente registrado de novo que não recupera nada,
  e `key.revoke` com prova, sem dar o uso;
- o que muda entre a decisão e o commit — a dona revogada, a chave
  destruída, o processo isolado, a política sem `key.sign` ou sem o
  domínio, a sessão revogada, a credencial e o agente suspensos, o papel
  do agente trocado — recusa a assinatura; e a chave não é da sessão: a
  pessoa assina com ela numa sessão nova;
- dois processos assinando ao mesmo tempo, e duas criações do mesmo nome;
- a declaração ancorada só na decisão de quem declara;
- o journal: a viva volta com a mesma privada, as lápides voltam, a
  compactação larga a semente da destruída, a revogação reposta não anula
  de novo, e sem o journal nada nasce nem se assina.

E com o IC (`icp:`), o programa lançado por uma pessoa operadora: a
chamada assinada e verificada, do anônimo também; cada chave um
Principal — duas da mesma pessoa, a de outra pessoa e a de um agente —; a
chamada pendente acompanhada, uma assinatura por leitura; o canister da
sub-rede raiz; as recusas da chamada; a chave anulada e a pessoa revogada
no meio do acompanhamento; sem chave ou sem a permissão; a prova
adulterada da chamada em cada lugar; e a contenção e o firewall no meio
do acompanhamento.

Na bancada de persistência: as chaves sobrevivem ao corte — a viva assina
igual, a destruída não assina —, a fotografia de antes da destruição é
recusada, e a queda em cada fronteira da criação e da destruição vale
exatamente quando o registro está no disco.

### A fumaça

Na sonda *o IC, pelo operador*, o agente da porta 2 cria a chave dele —
`chave:bancada`, no domínio `ic-request` — antes de lançar o
`verificado`, que, depois das consultas do ICP-1:

- chama o `quem` assinado pela chave do operador — o canister responde o
  Principal dela, e o programa confere que é o da pública que o
  `key.read` lhe deu — e do anônimo, que responde o Principal anônimo;
- mede cinco `contar` assinados, cinco do anônimo e cinco assinaturas
  sozinhas pelo `key.sign`.

Do lado de fora, além do que a sonda já conferia:

- cada execução de `key.sign` — `chave:bancada ic-request <resumo>` —
  cita a decisão dela, gravada antes;
- cada chamada assinada — o `quem` e os cinco `contar` — é declarada
  ancorada pelo kernel na decisão de uma assinatura do mesmo processo; a
  do anônimo, na conexão;
- onze assinaturas e onze decisões — seis chamadas e cinco sozinhas —,
  seis declarações ancoradas nelas, e vinte conexões para as oito
  consultas e as doze chamadas;
- as decisões do processo, todas `ALLOW` e só do que a consulta e a
  chamada pedem: as de antes, mais `key.read` e `key.sign`;
- nada do IC — além do que já se procurava, `icp.update`,
  `request_status` e `/api/v4/` — fora das declarações.

### As medidas

Na imagem de produção, a mediana dos cinco `contar` do `verificado`, em
ms: a chamada inteira — a hora e o nonce pelo gate, a conexão, a leitura
das faixas, a chamada pela `/api/v4` e a verificação do certificado da
resposta; a assinada, mais o `key.read` e o `key.sign` do id do pedido. E
o `key.sign` sozinho, cinco vezes, do pedido à resposta — a decisão, a
reconfirmação, o registro no journal e a assinatura:

| kernel de produção | x86 | ARM |
|---|---|---|
| depuração | assinada **700**, do anônimo 630; `key.sign` 20 (20 a 70) | assinada **630**, do anônimo 570; `key.sign` 30 (20 a 70) |
| release | assinada **530**, do anônimo 460; `key.sign` 10 (0 a 10) | assinada **430**, do anônimo 420; `key.sign` 10 (0 a 20) |

O relógio do programa é o `system.uptime`, que anda de 10 em 10 ms: o
`key.sign` sozinho é do tamanho da régua. A assinatura custa à chamada de
10 a 70 ms; o resto é o que a chamada do anônimo também faz. Na mesma
fumaça, as consultas do ICP-1 deram 470, 340, 230 e 240 ms, na ordem da
tabela.

### As mutações

Uma de cada vez, com o que a pega: a suíte do x86 só com os casos
`chaves:` — ou os `icp:` da chamada, quando a mutação é dela —, e os testes
do hospedeiro do pacote, quando ela é do `web3` ou da `politica`. As
dezessete pedidas morrem, e mais duas — a reconfirmação sem a contenção e
a compactação sem as lápides:

| mutação | onde | o que a pegou |
|---|---|---|
| sem o gate de `key.sign`: a permissão de ler basta | kernel | o programa assinou sem declarar `key.sign` |
| sem a conferência do dono: a chave de mesmo nome de qualquer dono assina | `chaves.rs` | a chave de outra identidade assinou; a revogação de um dono tocou as de outro; uma lápide reposta assinou |
| domínio arbitrário: o papel não precisa usar o domínio | kernel | a assinatura num domínio que o papel não usa passou |
| sem a reconfirmação no commit | kernel | o que mudou entre a decisão e o commit não recusou a assinatura |
| a reconfirmação sem a contenção | `autorizacao.rs` | idem: o processo isolado, o agente e a credencial suspensos assinaram |
| assinar antes da auditoria | kernel | a assinatura saiu sem o registro dela no journal |
| a privada na auditoria da assinatura | kernel | a assinatura não foi gravada com a chave, o domínio, o resumo e a impressão |
| sem lápide: a destruída sai da tabela | `chaves.rs` | seis casos: a destruição, a anulação e a revogação não deixaram nada |
| sem lápide no journal: a compactação esquece as mortas | `persistencia.rs` | as chaves repostas não são as de antes |
| o resumo de mais de 32 bytes aceito | kernel | um resumo fora da forma não foi recusado |
| a sessão como dono | `autorizacao.rs` | sete casos — entre eles, revogada a sessão, a chave não ficou com a pessoa |
| o administrador com a chave alheia: `owner` no pedido | kernel | a chave de outra identidade assinou para quem pediu |
| o sistema com `key.*` | `politica` | o sistema alcançou a chave de uma pessoa; e quatro testes da política (a emergência sem chave, o sistema enumerado) |
| exportar: `key.read` devolve a semente | kernel | a privada apareceu numa resposta |
| a declaração ancorada na decisão de outro | `autorizacao.rs` | uma âncora que não é de quem declara foi aceita |
| o 202 como resposta final | `web3` | `a_202_acompanhada_ate_a_resposta`; a chamada pendente não foi acompanhada |
| sem `request_status`: qualquer certificado é a resposta | `web3` | idem |
| sem a verificação do certificado da chamada | `web3` | `o_certificado_de_outra_sub_rede`; a chamada adulterada não foi recusada |
| o certificado adulterado aceito: a BLS não é conferida | `web3` | `a_assinatura_errada_e_recusada`; idem |

A da sessão como dono parecia morta na primeira rodada, em dois segundos:
era a mutação que não compilava, e a campanha contava a falha da
compilação como morte. A campanha passou a separar as duas, e a mutação,
escrita de novo, morreu em sete casos.

## O TLS público (ICP-4a)

A rede principal do IC fala por `icp-api.io`, atrás do certificado de uma
autoridade pública — e o perfil do TLS do Duke recusava toda cadeia
pública: só conferia ECDSA P-256 e Ed25519, e as raízes e os
intermediários das autoridades que importam são P-384 ou RSA — na Let's
Encrypt, as raízes X1 (RSA de 4096 bits) e X2 (P-384), os intermediários
ECDSA P-384 e os RSA de 2048 bits; na Google Trust Services, as raízes
R1 (RSA) e R4 (P-384). O ICP-4a dá ao programa a verificação dessas
cadeias, e só isso: a rede principal continua desligada, e nada mais do
Duke muda.

### O que mudou

Só o perfil de assinaturas do pacote [`tls`](../tls/src/assinatura.rs), que
é do programa:

| Algoritmo | Na cadeia | No `CertificateVerify` |
|---|---|---|
| ECDSA P-256 com SHA-256 | sim (já era) | `ecdsa_secp256r1_sha256` (já era) |
| ECDSA P-384 com SHA-384 | **sim** | **`ecdsa_secp384r1_sha384`** |
| Ed25519 | sim (já era) | `ed25519` (já era) |
| RSA PKCS#1 v1.5 com SHA-256, SHA-384 ou SHA-512 | **sim** | não: o TLS 1.3 não o aceita no aperto |
| RSA-PSS com SHA-256, SHA-384 ou SHA-512, chave `rsaEncryption` | não | **`rsa_pss_rsae_sha256`, `_sha384`, `_sha512`** |

As contas são do RustCrypto, como as de antes: o `p384` 0.14 e o `rsa`
0.10 (a candidata 19, fixa: a linha estável, a 0.9, está nas versões
antigas do `digest` e do `signature`), só na **verificação** — não há
chave privada RSA no Duke, nem cifra RSA, nem geração de chave fora dos
testes e da bancada. O `rsa` vem sem o `encoding`: a chave pública do
certificado é lida aqui, pelo `der` que o `ecdsa` já trazia.

A chave também tem perfil, e uma fora dele não confere assinatura nenhuma:

- **RSA:** o `RSAPublicKey` em DER estrito — nada depois da sequência,
  cada inteiro na forma mínima e positivo —; o módulo de 2048 a 4096 bits
  e múltiplo de 8 (a regra da CA/Browser Forum; 4096 é o das raízes
  públicas); o expoente ímpar, de 2^16 + 1 a 2^33 − 1. A assinatura tem o
  tamanho exato do módulo: o `rsa` aceitaria uma com o zero da frente
  cortado, e o RFC 8017 não. O PSS tem o sal do tamanho do hash (RFC 8446,
  4.2.3);
- **ECDSA:** só o ponto sem compressão — como o *ring* e o `webpki`
  exigem —, também na P-256, que antes aceitava o comprimido.

Fora do perfil, de propósito: SHA-1, P-521, a curva com o hash da outra
(P-256 com SHA-384, P-384 com SHA-256 — a regra da CA/Browser Forum, que
o *ring* não segue), o certificado assinado com RSA-PSS (que a CA/Browser
Forum permite e nenhuma das cadeias públicas encontradas usa), e o RSA
acima de 4096 bits. Um servidor com um deles é recusado no aperto com
`TLS_UNTRUSTED`, e não aceito com menos verificação.

**O que não mudou.** O código do kernel, a política, o gate, as
permissões, as identidades, o NSF e o `net.connect` — nenhuma linha
deles: os casos da suíte que mudaram contam as conexões novas do
programa e os pedaços do disco, que ficou menor (ver *O tamanho*). O TLS continua
no programa, e o resto da verificação é o de antes, do `webpki`: a cadeia
até uma âncora dada, a validade de cada certificado — da folha e de cada
intermediário — pela hora de quem conecta, o nome, o uso `serverAuth`, o
teto de seis intermediários. A âncora continua sendo a configuração da
imagem: o programa não aprende raiz pela rede, nem a que o servidor manda
junto. Os códigos `TLS_*` continuam do programa, e nenhum vira decisão do
gate.

### A bancada

O eco TLS da bancada ([`xtask/src/tls.rs`](../xtask/src/tls.rs)) ganhou as
cadeias com a forma das públicas — um intermediário entre a folha e a
raiz —, servidas pelo OpenSSL do hospedeiro, outra implementação inteira:

| nome | cadeia | o que o programa tem de dizer |
|---|---|---|
| `p384.duke` | raiz P-384 → intermediário P-384 → folha P-384 | aceita: a P-384 na cadeia e no aperto |
| `rsa.duke` | raiz RSA de 4096 → intermediário RSA de 2048 → folha RSA de 2048 | aceita: o PKCS#1 v1.5 na cadeia, o PSS no aperto |
| `misto.duke` | raiz RSA → intermediário P-384 → folha P-256 | aceita: a forma da cadeia ECDSA da Let's Encrypt pela X1 |
| `intruso.duke` | uma raiz RSA que o programa não tem, mandada junto | `TLS_UNTRUSTED` |
| `falso-p384.duke` | a de `misto.duke`, com um bit da assinatura da folha trocado | `TLS_UNTRUSTED` |
| `falso-rsa.duke` | a de `rsa.duke` até o intermediário, folha P-256 com um bit da assinatura trocado | `TLS_UNTRUSTED` |

As chaves RSA vêm do `rsa`, de um ChaCha20 semeado pelo sistema — o *ring*,
que o `rcgen` usa, não gera chave RSA —, em `target/bancada-tls`, fora do
repositório. A imagem tem as três raízes da bancada em
`/dados/tls/bancada.pem`: a P-256 de antes, a RSA e a P-384.

### Os casos

No hospedeiro (`cargo test -p tls`), o cliente conversa com o servidor do
`rustls` sobre o *ring*, e o que o perfil recusa é conferido contra o
cliente do `rustls` sobre o *ring*, que aceita a mesma cadeia — a recusa é
pelo algoritmo ou pela chave, e não por outro defeito dela. Na suíte, o
programa [`cifrado`](../programas/src/bin/cifrado.rs) fecha as três cadeias
e recusa as três falsas; o [`pausado`](../programas/src/bin/pausado.rs), que
os casos da política, do firewall e da contenção interrompem no meio,
conversa agora pela cadeia mista.

| | o que se confere | onde |
|---|---|---|
| 1 | P-256 continua | `o_aperto_fecha_e_o_eco_volta` e os de antes; `bancada.duke` na suíte |
| 2 | Ed25519 continua | `a_cadeia_ed25519_vale`, `ed25519_recusa_a_chave_de_ordem_pequena` |
| 3 | P-384 | `a_cadeia_p384_vale`, `p384_confere_e_recusa_a_outra_mensagem_e_o_outro_hash`; `p384.duke` |
| 4 | RSA | `cada_rsa_do_perfil_vale` (cada SHA-2, no PKCS#1 v1.5 e no PSS), `rsa_confere_cada_hash_e_cada_preenchimento`; `rsa.duke` |
| 5 | cadeia com intermediário | `a_cadeia_mista_das_autoridades_publicas_vale` — e sem o intermediário ela não fecha; `misto.duke` |
| 6 | cadeia inválida | `a_cadeia_quebrada_e_recusada`: o intermediário de outra raiz, uma folha no lugar de um intermediário |
| 7 | assinatura inválida | `a_assinatura_que_nao_confere_nas_cadeias_novas_e_recusada`, `rsa_recusa_a_assinatura_de_outro_tamanho_ou_trocada`, `pss_recusa_o_sal_de_outro_tamanho`; `falso-p384.duke` e `falso-rsa.duke` |
| 8 | vencido | `a_validade_nas_cadeias_novas` — a folha e o intermediário —; `vencido.duke` |
| 9 | ainda não válido | `a_validade_nas_cadeias_novas`; `futuro.duke`, no `validade` |
| 10 | nome errado | `o_nome_errado_nas_cadeias_novas_e_recusado`; `outro.duke` |
| 11 | autoridade não confiável | `a_raiz_que_o_servidor_manda_nao_vira_ancora`; `estranho.duke` e `intruso.duke` |
| 12 | algoritmo fora do perfil | `a_curva_com_o_hash_da_outra_e_recusada` (o *ring* aceita), `a_lista_do_perfil_e_exatamente_esta` |
| 13 | chave pública inválida | `a_chave_publica_fora_do_perfil_e_recusada` (o RSA de 1024 bits, o expoente 3 — que o *ring* aceita —, o módulo fora da forma mínima, o ponto comprimido), `a_chave_rsa_so_se_le_no_perfil`, `rsa_recusa_a_chave_curta_e_o_expoente_pequeno` |
| 14 | certificado malformado ou cortado | `o_certificado_torto_e_recusado` |
| 15 | cadeia longa demais | `a_cadeia_longa_demais_e_recusada`: seis intermediários fecham, sete não |
| 16 | a política, o firewall e a contenção no meio da sessão | `tls: a politica que tira o destino derruba a sessao`, `tls: o firewall barra a conexao nova com o codigo dele`, `tls: o processo isolado perde a sessao` — pela cadeia mista —; `a_recusa_do_transporte_vale_igual_nas_cadeias_novas` |
| 17 | o `net.connect` como era | `tls: o programa cifrado conversa pelo gate`: dez nomes, dez decisões `ALLOW` iguais do mesmo destino; a porta ao lado, `DENY_RESOURCE` antes do TLS |
| 18 | nenhum desvio pelo TLS | o mesmo caso, `tls: sem random.read nada sai`, `os_codigos_do_tls_nao_sao_do_gate`, e o `xtask invariantes` — nenhum verificador próprio, nenhum `dangerous()` |

### O tamanho

O P-384 e o RSA puseram uns 100 KB em cada programa com TLS — a maior
parte, a aritmética do RSA —, e o `icp` e o `verificado` passaram do teto
de leitura do kernel, 1 MiB (1 107 432 e 1 108 944 bytes no x86): o
código não se lia, e os casos do IC caíam com "o arquivo nao cabe no teto
de leitura". O teto ficou como está — ele protege o heap, por onde cada
lançamento passa inteiro. Os programas perderam a tabela de símbolos
(`strip = "symbols"` no perfil de release de `programas/`), que nada lia:
o kernel carrega pelos cabeçalhos e pelo manifesto, `.note.duke`, que
fica, e o `xtask simbolo` é do kernel. Ela era um sexto de cada programa:

| programa | antes do ICP-4a | com o P-384 e o RSA | sem a tabela de símbolos |
|---|---|---|---|
| `icp`, x86 | 1 011 032 | 1 107 432 | 924 520 |
| `icp`, ARM | 997 056 | 1 095 104 | 819 728 |
| `cifrado`, x86 | 642 336 | 738 696 | 592 552 |
| todos, x86 | 11,6 MB | 12,9 MB | 10,6 MB |
| todos, ARM | 12,1 MB | 13,4 MB | 9,6 MB |

O crescimento também achou um defeito da bancada: com os dados maiores, o
`mkfs.btrfs --rootdir` aumentou o arquivo da raiz para 133 MiB, calado, e
o `xtask` o copiou por cima do começo da partição seguinte — o caso do
superbloco pegou, longe da causa. O `xtask` agora recusa a partição maior
que o lugar dela. Com os programas menores, a raiz voltou a quatro
pedaços de dados.

### As medidas

O aperto de cada cadeia, como o `cifrado` o diz — do `net.connect` ao
servidor provado, com a régua de 10 ms do `system.uptime` —, numa
rodada de cada:

| cadeia | x86, suíte | x86, fumaça | ARM, fumaça |
|---|---|---|---|
| `bancada.duke` — P-256 | 150 ms | 170 ms | 120 ms |
| `p384.duke` — P-384 na cadeia e no aperto | 170 ms | 130 ms | 120 ms |
| `rsa.duke` — RSA de 4096 e de 2048, o PSS no aperto | 110 ms | 130 ms | 100 ms |
| `misto.duke` — RSA, P-384 e P-256 | 100 ms | 120 ms | 100 ms |
| o `cifrado` inteiro — doze conexões, quatro conversas | 3,6 s | 5,9 s | 4,7 s |

As cadeias novas custam o que a P-256 custa: o RSA verifica com o
expoente 65537 — dezessete multiplicações —, e a P-384 é uma conta por
elo. O que domina o aperto é o resto dele, igual nas quatro. Os três
`cifrado` ao mesmo tempo da suíte levam uns 12 s no x86, de um teto de
60.

### As mutações

Uma de cada vez, com o que a pega: os testes do pacote `tls` no
hospedeiro (`cargo test -p tls`), e a suíte do x86 só com os casos `tls:`
quando a mutação chega ao programa ou ao kernel. As sete pedidas — em
onze formas, as onze primeiras da tabela — e dez do perfil novo: vinte e
uma, todas reprovadas.

| mutação | onde | no hospedeiro | na suíte |
|---|---|---|---|
| **o nome não é conferido** | `sessao.rs`: um verificador que engole `NotValidForName` | `o_nome_errado_e_recusado`, `o_nome_errado_nas_cadeias_novas_e_recusado` | `outro.duke` aceito |
| **a autoridade desconhecida é aceita** | `sessao.rs`: engole `UnknownIssuer` | `a_raiz_desconhecida_e_recusada`, `a_raiz_que_o_servidor_manda_nao_vira_ancora`, `a_cadeia_quebrada_e_recusada`, `a_cadeia_mista_das_autoridades_publicas_vale` (sem o intermediário) | `estranho.duke` aceito |
| **o vencido é aceito** | `sessao.rs`: engole `Expired` | `a_validade_nas_cadeias_novas`, `o_vencido_e_o_que_ainda_nao_vale_sao_recusados`, `o_relogio_de_quem_conecta_decide_a_validade` | `vencido.duke` aceito, e o caso da validade pela hora autenticada |
| **a assinatura P-384 não é conferida** | `assinatura.rs` | `p384_confere_e_recusa_a_outra_mensagem_e_o_outro_hash`, `a_assinatura_que_nao_confere_nas_cadeias_novas_e_recusada` | `falso-p384.duke` aceito |
| **a assinatura RSA PKCS#1 v1.5 não é conferida** | `assinatura.rs` | `rsa_confere_cada_hash_e_cada_preenchimento`, `rsa_recusa_a_assinatura_de_outro_tamanho_ou_trocada`, `a_assinatura_que_nao_confere_nas_cadeias_novas_e_recusada` | `falso-rsa.duke` aceito |
| **a assinatura RSA-PSS não é conferida** | `assinatura.rs` | `pss_recusa_o_sal_de_outro_tamanho`, `rsa_confere_cada_hash_e_cada_preenchimento`, `a_assinatura_que_nao_confere_nas_cadeias_novas_e_recusada` | — |
| **a curva com o hash da outra é aceita** — a P-384 com o SHA-256 na cadeia | `assinatura.rs`: mais um algoritmo na lista | `a_curva_com_o_hash_da_outra_e_recusada`, `a_lista_do_perfil_e_exatamente_esta` | — |
| **o gate deixa o `net.connect` fora do alcance** | kernel, `autorizacao.rs` | — | a porta ao lado, que nenhum papel alcança, foi conectada — `NETWORK_TIMEOUT`, e não `DENY_RESOURCE` —; e, tirado o destino da política no meio da sessão, o `pausado` mandou |
| **a recusa do gate no meio da sessão é engolida pelo TLS** | `sessao.rs` | `a_recusa_do_transporte_passa_adiante_sem_traducao`, `a_recusa_do_transporte_vale_igual_nas_cadeias_novas`, `a_sessao_que_falhou_nao_volta` | — |
| **a recusa do TLS vira sessão aceita** | `sessao.rs` | vinte casos: toda recusa da conversa | `outro.duke` aceito, e o caso da validade |
| **`TLS_UNTRUSTED` vira `ALLOW`** | `falha.rs` | `os_codigos_do_tls_nao_sao_do_gate` | na fumaça: "o cifrado nao disse `estranho.duke -> TLS_UNTRUSTED`" |
| o PSS também na cadeia | `assinatura.rs` | `a_lista_do_perfil_e_exatamente_esta` | — |
| o módulo RSA de 1024 bits | `assinatura.rs` | `a_chave_rsa_so_se_le_no_perfil`, `rsa_recusa_a_chave_curta_e_o_expoente_pequeno`, `a_chave_publica_fora_do_perfil_e_recusada` | — |
| o módulo RSA de 8192 bits | `assinatura.rs` | `a_chave_rsa_so_se_le_no_perfil` | — |
| o módulo fora do múltiplo de 8 | `assinatura.rs` | `a_chave_rsa_so_se_le_no_perfil` | — |
| o expoente 3 | `assinatura.rs` | `a_chave_rsa_so_se_le_no_perfil`, `rsa_recusa_a_chave_curta_e_o_expoente_pequeno`, `a_chave_publica_fora_do_perfil_e_recusada` | — |
| a assinatura RSA de outro tamanho | `assinatura.rs` | `rsa_recusa_a_assinatura_de_outro_tamanho_ou_trocada` | — |
| o PSS com qualquer sal | `assinatura.rs` | `pss_recusa_o_sal_de_outro_tamanho` | — |
| o ponto ECDSA comprimido | `assinatura.rs` | `ecdsa_recusa_o_ponto_comprimido_e_o_fora_da_curva`, `a_chave_publica_fora_do_perfil_e_recusada` | — |
| o DER da chave RSA com sobra | `assinatura.rs` | `a_chave_rsa_so_se_le_no_perfil` | — |
| o SHA-384 do PKCS#1 conferido como SHA-256 | `assinatura.rs` | `rsa_confere_cada_hash_e_cada_preenchimento`, `cada_rsa_do_perfil_vale` | — |

As três primeiras são o atalho que o `xtask invariantes` procura — um
verificador próprio, pela API `dangerous()` do `rustls` —, e ele as recusa
antes de qualquer teste, nas três linhas: "um atalho na verificação do
TLS". Os testes as pegam também: sem a conferência estática, o nome, a
autoridade e a validade continuam conferidos por casos que reprovam.

As que não chegam à suíte não chegam de propósito. O OpenSSL da bancada
não assina o aperto com uma chave que não é a do certificado — ele confere
o par ao carregar —, e a bancada só serve cadeias do perfil e as recusadas
pela confiança, pelo nome, pela validade e pela assinatura da cadeia; a do
TLS que engole a recusa do gate no meio da sessão é vista pelo `pausado`
na leitura seguinte, que o gate também recusa. Todas morrem no
hospedeiro, onde o servidor e as cadeias são feitos sob medida.

## O que não existe ainda

De propósito, e cada um é uma decisão nova quando vier: delegações — e,
com elas, chaves de sessão e o domínio de delegação —; a custódia no TPM;
o compartilhamento de chaves; exportar ou importar uma privada; a rede
principal do IC; *cycles*; implantar canisters; o `icp-cli` dentro do
Duke; o CDK; a EVM; o HTTP/3. Nem mudança no DNS, no TCP ou no HTTP: o
ICP-1 e o ICP-3 rodam sobre a infraestrutura que já existia, e o gate
decide as chaves como decide tudo. O TLS mudou uma vez, no ICP-4a — o
perfil de assinaturas do programa, para as cadeias públicas —, e a rede
principal continua desligada: as âncoras dela, os endereços dos *API
boundary nodes* e a raiz do IC na imagem são o passo seguinte.
