# O QUIC e o HTTP/3: a avaliação

O roteiro põe o HTTP/3 entre os incrementos de infraestrutura da fase 12
com uma condição: "o HTTP/3, que depende do QUIC e começa por uma
avaliação" ([Roteiro](../README.md#roteiro)). Esta é a avaliação. O dossiê
das decisões a classifica como [B] — trabalho que começa já, sem esperar o
dono ([R12-QUIC](DECISOES.md#r12-quic)) —, e por isso este documento **não
implementa nem decide nada**: diz o que o Duke já tem e serve ao QUIC, o
que falta, como uma conexão QUIC encaixaria no gate e na política, se
alguém no Duke precisa dela, quanto custaria, e o que pediria uma decisão
do dono ([5.3](../CLAUDE.md#53-as-decisões-c)) — no formato curto do
dossiê, para ir a ele depois.

**Como ler.**

- As fontes são as do commit `f19df2d`, de 17/11/2026, e as linhas
  citadas, na forma `arquivo:linha`, são as dele. O README, o
  `kernel/src/autorizacao.rs` e o `xtask/src/main.rs` mudavam noutro
  trabalho enquanto este documento era escrito: se as linhas deles
  andarem, vale o texto citado.
  As do `rustls` são as da versão do `Cargo.lock`, a 0.23.45
  (`rustls-0.23.45/src/…`, no registro do cargo), e as do `smoltcp`, as
  da 0.14.0. As RFCs vão citadas pela seção.
- Os tamanhos dos programas são os registros de proveniência do mesmo
  commit (`target/proveniencia/`, ver
  [4.4](../CLAUDE.md#44-a-proveniência)), em release, com o compilador
  oficial: `nightly-2026-11-15`, `rustc 1.102.0-nightly (5f4effd57
  2026-11-13)`. Os registros dizem `"arvore_limpa": false`: a árvore
  tinha o trabalho em curso no kernel, no README e no `xtask`, que não
  entra nos programas.
- Uma estimativa, uma alternativa ou uma recomendação que não sai das
  fontes nem decorre direto das invariantes leva **(minha)**, como no
  dossiê. Um número "a medir" é conta, e não medida.

## A resposta curta

- **Adiar (minha, pelo grupo C e pela bancada).** Nenhum consumidor do Duke ganha com o HTTP/3 hoje. O IC está
  fora pelo grupo C; os servidores da bancada falam HTTP/1.1 e HTTP/2; e o
  que o HTTP/3 traria de novo — a perda de um pacote sem segurar as outras
  correntes, uma volta a menos para abrir a conexão — não aparece numa
  bancada sem perda, com a volta abaixo de um milissegundo, em que o custo
  de cada pedido é o caminho dele dentro do Duke. Fazer agora seria
  escrever um transporte inteiro — de duas a três vezes o código do
  HTTP/2, e de três a cinco vezes o incremento dele **(minha)** — sem quem
  o use.
- **Caberia no gate de hoje, sem regra nova,** no caminho que esta
  avaliação recomenda para quando a necessidade vier: só o cliente, um
  caminho só, sem migração, sem 0-RTT, sem seguir o endereço preferido do
  servidor. Uma conexão QUIC de cliente é uma associação `udp:` com um
  destino só, decidida pelo gate, e a RFC 9000 exige do cliente o que a
  associação já faz: descartar o que chega de outro endereço.
- **Mas não sem custo, nem sem uma decisão.** O QUIC mede o tempo de cada
  pacote, e o relógio de um programa é uma decisão do gate que gasta a
  taxa do papel: dar ao programa um relógio no ritmo dos pacotes é [C]
  ([R12-QUIC-RELOGIO](#r12-quic-relogio)). E há três trabalhos [B] antes:
  o buffer da associação, que guarda dois datagramas cheios; uma decisão
  do gate por datagrama — de 13 a 22 vezes as decisões do TCP por MiB
  **(minha, a medir)**; e a API do QUIC do `rustls`, que só existe com
  `std`.
- **De fora:** o 0-RTT, dados que se repetem — a recomendação é não, e
  só com uma necessidade ([R12-QUIC-0RTT](#r12-quic-0rtt)) —; e, com a
  recomendação de nunca, a mudança de caminho seguida pelo kernel, um
  destino que mudaria sem o gate ([R12-QUIC-CAMINHO](#r12-quic-caminho)). E fora do assunto: o Duke como
  servidor HTTP/3, que pediria entrada de rede para programas.

## O que já existe e serve

### A associação UDP pelo gate

O UDP de um programa é uma **associação**: `net.connect` com
`udp:<ipv4>:<porta>` — o mesmo comando, a mesma permissão e a mesma
decisão pelo destino inteiro que o TCP ([Rede
nativa](../README.md#rede-nativa), README.md:2687-2725;
`politica/src/endereco.rs:19-26`). O DNS dos programas a usa
(`programas/src/dns.rs:139-190`), e o serviço de hora também, com o
Roughtime. Para um cliente QUIC, ela já é quase tudo:

- **Um destino só, nos dois sentidos.** O datagrama que sai vai sempre ao
  destino da associação (`kernel/src/rede/pilha.rs:1280`), e o que chega
  de outro endereço ou de outra porta é descartado na volta da pilha em
  que chega à frente da fila, e contado (`pilha.rs:969-983`, chamado em
  `:892-897`). É o que a RFC 9000 pede do cliente: só o cliente inicia
  uma migração, e o cliente que recebe pacotes de um endereço de servidor
  que não conhece os descarta (§9).
- **O datagrama inteiro, sem fragmentação.** Até 1472 bytes, o quadro
  menos os cabeçalhos (`pilha.rs:144-148`; `kernel/src/rede/placa.rs:26`)
  — acima dos 1200 que o QUIC exige nos datagramas que levam o Initial
  (RFC 9000 §14.1). O QUIC proíbe a fragmentação no IP e pede o DF ligado
  (§14); o `smoltcp` liga o DF em todo IPv4 que emite
  (`smoltcp-0.14.0/src/wire/ipv4.rs:607`), e o kernel não liga a
  fragmentação dele (`kernel/Cargo.toml:124-133`).
- **A decisão a cada uso.** Cada `net.send` e cada `net.recv` nomeia a
  associação pelo número, que o gate resolve no destino **para quem pede**
  antes de decidir (`kernel/src/autorizacao.rs:2895-2921`;
  `kernel/src/rede/conexoes.rs:186-191`), e vai à auditoria com o
  destino; a revogação, a contenção, a política nova e o firewall valem no
  pedido seguinte (README.md:2648-2654, e a contenção em 3385-3387;
  `pilha.rs:1270-1274`). Sobre a associação aberta, viva e de quem pede —
  com quem pede não contido, e o pedido autorizado (`autorizacao.rs:2540-2542`,
  `:2562-2564`) —, o pedido é do plano de dados:
  passa pelo gate e não gasta a ficha do papel
  (`autorizacao.rs:2543-2584`; `kernel/src/agent/registry.rs:166-201`).
- **A espera, sem girar.** Uma de cada sentido, até dez segundos
  (`kernel/src/rede/espera.rs:107`). O datagrama de outra origem acorda a
  espera, a conferência não acha nada, e ela continua (`espera.rs:9-11`):
  quem manda lixo à porta da associação não gera decisões.
- **O dono, o teto e o fim.** A associação é do processo, e cai quando ele
  acaba (`conexoes.rs:55-67`, `:208-243`); conta no teto de quatro por
  titular e dezesseis na máquina (`pilha.rs:112-117`); tem a porta local
  só dela (`pilha.rs:1048-1067`).

As promessas da associação — o destino só, o datagrama inteiro, o teto do
quadro, a fila, a porta própria, a espera, o protocolo como parte do
destino — têm mutação: trinta, todas reprovadas ([As mutações do
UDP](../README.md#as-mutações-do-udp)); as da decisão a cada uso, as da
rede ([As mutações da rede](../README.md#as-mutações-da-rede)).

O que **não** serve como está:

- **O buffer.** Quatro KiB e oito datagramas em cada sentido
  (`pilha.rs:135-138`, `:150-152`): cabem dois datagramas de 1472 bytes,
  ou três de 1200 — o anel guarda cada datagrama contíguo
  (`smoltcp-0.14.0/src/storage/packet_buffer.rs:80-118`), e depois da
  volta dele o enchimento pode deixar menos. O
  servidor QUIC abre com uma janela de até dez datagramas cheios (RFC 9002
  §7.2); a placa recebe a rajada — dezesseis buffers de recepção
  (README.md:3346-3355) —, mas a associação não a guarda, e o resto se
  perde na entrada. Cada perda corta a janela do congestionamento do
  servidor. A escolha está escrita: a associação "continua com 4 KiB em
  cada sentido", e a suíte confere que ela não acompanha o TCP
  (README.md:3377-3379).
- **Um datagrama por decisão** (README.md:2700-2709). O custo está em [O
  custo de um datagrama por decisão](#o-custo-de-um-datagrama-por-decisão).

### O TCP, a janela e o plano de dados

O TCP é do `smoltcp`, no kernel — o aperto, as retransmissões, o
congestionamento —, e o lado de cima é do Duke: a janela de 16 KiB, que é
o buffer da conexão, com um `net.recv` levando vários segmentos numa
decisão ([A janela do TCP](../README.md#a-janela-do-tcp)); e o plano de
dados, em que os envios e as leituras pela conexão aberta saem da taxa do
papel para a capacidade do caminho da auditoria ([O plano de
dados](../README.md#o-plano-de-dados)) — o anel de 1024 registros, a
partilha a partir de 640 pendentes, a espera a partir de 768
(`kernel/src/oleoduto.rs:71-81`).

Nada disso o QUIC reaproveita como código: a recuperação de perdas e o
congestionamento, que no TCP são do kernel, no QUIC são do programa. Ele
herda as medidas, que servem de régua:

- um MiB pelo TCP custa perto de 85 decisões do gate (README.md:3417-3418);
- uma decisão leva de 280 a 465 µs, conforme a medida e a arquitetura
  (README.md:3189-3190, 3524);
- o NSF lê até 512 registros por volta, uma volta por segundo, com a taxa
  do papel dele, e o que fica para trás o declara degradado
  (README.md:3565-3569; [SEGURANCA, Limitações
  deliberadas](SEGURANCA.md#limitações-deliberadas)).

### O TLS dos programas

O pacote [`tls`](../tls/src/lib.rs) é o `rustls` 0.23.45 sem `std` — a
máquina de estados sem E/S, `UnbufferedClientConnection`
(`tls/src/sessao.rs:4-12`) —, com o provedor de cifra próprio
([`provedor.rs`](../tls/src/provedor.rs)): as três suítes do TLS 1.3, o
ChaCha20-Poly1305 primeiro, porque sem SIMD nem AES-NI nos processos ele
cifrou 317 MiB/s no hospedeiro, contra 104 do AES-128-GCM
(README.md:2848-2855); X25519 e P-256; as assinaturas das cadeias das
autoridades públicas, e nenhum atalho na verificação — o `xtask` proíbe a
API `dangerous()` (`xtask/src/main.rs:5597-5608`). O programa dá a ele a
semente de cada conexão (`random.read`), a hora da validade (o
`system.info`: o civil autenticado pelo Roughtime, ou o lógico, e nunca o
RTC cru), as âncoras (um PEM por `fs.read`) e o transporte ([O TLS de um
programa](../README.md#o-tls-de-um-programa); `programas/src/tls.rs:1-26`).
O ALPN existe desde o HTTP/2 (`Sessao::conectar_com_protocolos`,
`tls/src/sessao.rs:188`; `protocolo`, `:252`). O perfil é estreito de
propósito: sem retomada de sessão — desligada na configuração
(`sessao.rs:213`) —, sem 0-RTT, sem certificado de cliente
(`tls/src/lib.rs:48-49`; README.md:2893-2902).

O QUIC usa o TLS 1.3 para o aperto, e só troca o registro pelos quadros
dele: o aperto, a verificação, as âncoras, a hora e a semente se
reaproveitam inteiros.

O que **não** serve como está:

- **A API do QUIC do `rustls` só existe com `std`.** O
  `quic::ClientConnection`, com o `read_hs` e o `write_hs` que levam as
  mensagens do aperto sem o registro, está atrás de `#[cfg(feature =
  "std")]` (`rustls-0.23.45/src/quic.rs:18-19`, `:470-471`, `:488-489`),
  e o modo QUIC de uma conexão só se cria por ali — o construtor de dentro
  é do pacote (`ConnectionCore::for_client`, com `Protocol::Quic`). Sem
  `std`, existem as chaves do Initial (`Keys::initial`, `quic.rs:913`) e
  os traços que o provedor implementa (`Algorithm`, `HeaderProtectionKey`,
  `PacketKey`, `quic.rs:634-811`). Os alvos dos programas não têm `std`
  (`x86_64-unknown-none`, `aarch64-unknown-none-softfloat`).
- **O provedor não tem a parte do QUIC.** As três suítes vão com `quic:
  None` (`tls/src/provedor.rs:42`, `:55`, `:68`): não há a cifra do pacote
  nem a proteção do cabeçalho.

### O HTTP/1.1 e o HTTP/2

O pacote [`http`](../http/src/lib.rs), sem dependência nenhuma, tem o
cliente HTTP/1.1 (RFC 9112) e o HTTP/2 (RFC 9113), com o HPACK (RFC
7541): a URL, o pedido, a resposta, os limites, a família de cada falha, a
compressão, o pote de cookies, as correntes com teto — dezesseis por
conexão, 64 KiB de janela cada —, o *push* desligado e uma conexão por
origem ([O HTTP/2](../README.md#o-http2); README.md:4139-4143). O HTTP/3
leva a mesma semântica por outro enquadramento, e por isso reaproveita:

- a URL, o pedido, a resposta, os `Limites` e a taxonomia (`Erro`,
  `categoria`) — com códigos próprios, como o HTTP/2 ganhou os dele;
- a conferência da cabeça de uma resposta: os pseudo-cabeçalhos, os nomes
  em minúsculas, os cabeçalhos da conexão proibidos, o `:status` de três
  dígitos, as informativas, o `content-length` contra o corpo, os
  *trailers* (`http/src/h2.rs:104-110`, `:1328`, `:1344`). As regras da
  RFC 9114 (§4.2, §4.3) são as da RFC 9113 (§8.2, §8.3) **(minha leitura,
  a conferir regra a regra)**;
- o código de Huffman ([`huffman.rs`](../http/src/huffman.rs)): o QPACK usa
  o do HPACK (RFC 9204 §4.1.2);
- a disciplina do codificador do HPACK — nada indexado deste lado, e o
  `cookie`, o `authorization` e o `proxy-authorization` como nunca
  indexados: as representações do QPACK têm o mesmo bit (§4.5);
- a compressão (`codificacao`) e os cookies (`Pote`), que são do corpo e
  da cabeça, e não do enquadramento.

Não se reaproveitam os quadros do HTTP/2
([`quadro.rs`](../http/src/quadro.rs)) — os do HTTP/3 são outros, com
inteiros de tamanho variável e sem controle de fluxo, que passa ao QUIC —
nem a tabela dinâmica do HPACK: a do QPACK é outra, e o cliente pode
recusá-la (ver [O HTTP/3 e o QPACK](#o-http3-rfc-9114-e-o-qpack-rfc-9204)).

### Como um programa usa tudo isso

O programa declara `net.connect` no manifesto, e o papel de quem o lança
enumera os destinos — a imagem de desenvolvimento dá ao operador os da
bancada (`politica/src/lib.rs:383`). O `programas::http::conectar` segue
a ordem de quem falha fechado: a URL; com `https`, a semente e a hora; o
nome pelo DNS do programa; `net.connect` com o destino inteiro; o TLS; e
os pedidos, cada envio e cada leitura decididos de novo
(`programas/src/http.rs:5-31`). O transporte TCP
([`programas::conexao`](../programas/src/conexao.rs)) separa a recusa do
gate, o código de depois dele, a conexão recusada, a derrubada e o prazo,
e espera sempre com `wait`. A associação UDP não tem um transporte assim:
o DNS chama o `nativo` direto (`programas/src/dns.rs:139-190`).

O relógio que o projeto dá a um programa é o `nativo::uptime_ms`, que pede o
`system.uptime` ao gate a cada leitura e anda de 10 em 10 ms
(`programas/src/nativo.rs:236-244`). O comando é do plano de controle
(`kernel/src/agent/commands.rs:316-324`): cada leitura é uma decisão, um
registro e uma ficha da taxa do papel (`autorizacao.rs:2551`).

Os programas que falam HTTP — os da bancada (`pagina`, `buscador`,
`correntes`, `compressao`, `cookies`, `vazao`, `validade`), os do IC
(`icp`, `consulta`, `livro`, `verificado`, `carteira`, `implantacao`,
`gestor`) e o `instalador` — levam o cliente HTTP/2 mesmo quando só falam
HTTP/1.1, porque o protocolo se escolhe ao conectar (README.md:4158-4164).
Os seis maiores e, da bancada, os dois que o HTTP/2 mais exercita — o
`cookies`, 707 024 no x86, fica entre eles —, em bytes:

| Programa | x86 | ARM | Do teto, no x86 |
|---|---|---|---|
| `gestor` | 987 048 | 860 688 | 94,1% — faltam 60 KiB |
| `implantacao` | 941 520 | 823 824 | 89,8% |
| `carteira` | 925 144 | 807 440 | 88,2% |
| `icp` | 920 592 | 799 248 | 87,8% |
| `verificado` | 895 552 | 782 864 | 85,4% |
| `livro` | 874 952 | 762 384 | 83,4% |
| `correntes` | 698 576 | 614 928 | 66,6% |
| `buscador` | 690 384 | 610 832 | 65,8% |

O teto é o maior executável que o kernel lança, 1 MiB
(`protocolo/src/usuario.rs:1346`); o `xtask` recusa o que passa dele e
avisa acima de nove décimos (`xtask/src/main.rs:8304-8321`).

## O que o QUIC pede, e o que falta

| Peça | RFC | O que se reaproveita | O que é novo | Código **(minha)** |
|---|---|---|---|---|
| O transporte | 9000 | nada como código; a disciplina dos tetos e das recusas do HTTP/2 | pacotes de cabeçalho longo e curto, números de pacote, inteiros de tamanho variável, uns vinte tipos de quadro, IDs de conexão, parâmetros de transporte, correntes e controle de fluxo, fecho, prazo de ociosidade, reset sem estado, Retry, negociação de versão, a resposta à validação de caminho | 2 700–3 600 linhas |
| O TLS no QUIC | 9001 | o `rustls` inteiro — o aperto, a verificação, as âncoras, a hora, a semente —, as cifras, os resumos e as trocas do provedor | o modo QUIC do `rustls` sem `std`; a cifra do pacote e a proteção do cabeçalho no provedor; o aperto por nível de cifra | 400–700, mais o acesso ao `rustls` |
| A recuperação e o congestionamento | 9002 | nada: no TCP, é do kernel | a volta (RTT), as confirmações, a perda por limiar e por tempo, o PTO, o NewReno | 700–1 000 |
| O HTTP/3 | 9114 | o pedido, a resposta, os limites, a conferência da cabeça, a compressão, os cookies, a taxonomia | os quadros, a corrente de controle, o `SETTINGS`, o `GOAWAY`, os tipos desconhecidos ignorados, os códigos de erro | 900–1 300 |
| O QPACK | 9204 | o Huffman do HPACK; a disciplina do codificador | a tabela estática de 99 entradas, as representações | 400–600 |
| O programa | — | a ordem do `programas::http`, o DNS, o TLS | o transporte da associação; o `conectar` do HTTP/3 à parte; o programa da bancada | 300–600 |
| O kernel | — | a associação, a espera, o plano de dados | o buffer; o lote; o relógio, se decidido | 200–550 |
| **Soma** | | | | **5 600–8 350** |

A régua é o HTTP/2: o `h2.rs`, o `quadro.rs`, o `hpack.rs` e o
`huffman.rs` somam 2 642 linhas de código e 3 154 de testes, e
acrescentaram de 40 a 50 KiB a cada programa que fala HTTP, no x86
(README.md:4158-4161).

### O transporte (RFC 9000)

O QUIC é um transporte inteiro dentro do processo: os pacotes (§17), os
inteiros de tamanho variável (§16), os números de pacote truncados e
reconstruídos (§17.1), os quadros (§19), os IDs de conexão (§5.1), os
parâmetros de transporte (§7.4, §18), as correntes e o controle de fluxo
de cada uma e da conexão (§2–§4), o prazo de ociosidade, o fecho imediato
e o reset sem estado (§10), a validação do endereço e o Retry (§8.1), a
negociação de versão (§6) e a resposta às sondas de caminho do servidor
(§8.2). Só o lado do cliente, e só a versão 1. É a peça maior e a mais
nova: o Duke não tem nada parecido — o TCP é do `smoltcp` —, e o que o
HTTP/2 ensina é a forma de recusar, com o alcance de cada erro e um teto
para cada coisa que o par faz crescer: as correntes, os dados fora de
ordem (§21.7), os IDs, os quadros sem progresso (§21.9).

### O TLS dentro do QUIC (RFC 9001)

- **Sem o registro.** As mensagens do aperto vão em quadros `CRYPTO`, por
  nível de cifra — Initial, Handshake e 1-RTT (§4) —, e o `rustls` as dá e
  as recebe sem o registro, no modo QUIC.
- **A cifra do pacote** (§5.3): o AEAD da suíte, com o nonce do IV e do
  número do pacote, e o cabeçalho como dado associado — os mesmos AEAD do
  [`cifra.rs`](../tls/src/cifra.rs), com outro nonce e outro dado
  associado.
- **A proteção do cabeçalho** (§5.4): uma máscara de uma amostra de 16
  bytes do texto cifrado — o AES de um bloco nas suítes AES, o ChaCha20
  com o contador e o nonce da amostra na suíte ChaCha. Sai das primitivas
  que o projeto já tem — o AES de um bloco, do pacote `aes` que o
  `aes-gcm` reexporta com a feature `aes` (`tls/Cargo.toml:31`), e o
  ChaCha20 cru do pacote `chacha20` 0.10.2, o do gerador do `sigilo`
  (`sigilo/Cargo.toml:35`; `sigilo/src/gerador.rs:25-26`), que no `tls`
  passaria de dependência de teste (`tls/Cargo.toml:63`) a dependência —,
  sem pacote novo no `Cargo.lock`. É uma construção nova sobre primitivas
  que existem, fixada pela RFC, e não uma primitiva nova no sentido de
  5.3: **[B]**, classificada pelo coordenador. Fica [B] com os vetores do
  apêndice A da RFC 9001, a conferência contra o provedor do *ring*
  (`rustls-0.23.45/src/crypto/ring/tls13.rs:34`, `:54`, `:76`) e o
  adversário olhando o uso cru do AES e o contador do ChaCha20; uma
  primitiva fora das que existem, uma implementação própria de alguma
  delas, ou uma chave exportada, seria [C].
- **O Initial é sempre AES-128-GCM** (§5.2), com as chaves derivadas do ID
  de conexão que o cliente escolhe, pelo HKDF-SHA256; e a etiqueta de
  integridade do Retry também (§5.8). Mesmo com o ChaCha20 negociado, toda
  conexão faz AES-128-GCM em software nos primeiros pacotes.
- **A troca de chave** (§6) e **os limites por chave** (§6.6): no
  AES-GCM, 2^23 pacotes cifrados por chave, e 2^52 pacotes forjados; no
  ChaCha20-Poly1305, 2^36 forjados. Os limites de hoje do provedor são de
  registros do TLS (`provedor.rs:38`, `:51`); os do QUIC são por pacote.
- **O ALPN é obrigatório** (§8.1) — `h3` para o HTTP/3 (RFC 9114 §3.2) —, e
  os parâmetros de transporte vão numa extensão do aperto (§8.2), que o
  `rustls` leva no modo QUIC.

O que é novo no pacote `tls`: o acesso ao modo QUIC sem `std`; o
`quic::Algorithm` das três suítes no provedor — a cifra do pacote, a
proteção do cabeçalho e os limites; e uma sessão do aperto por nível, ao
lado da [`Sessao`](../tls/src/sessao.rs) de hoje. A forma do provedor
está no próprio `rustls`: o do *ring* implementa os três traços
(`rustls-0.23.45/src/crypto/ring/quic.rs`, 533 linhas com os testes), com
os limites da §6.6 em cada suíte (`src/crypto/ring/tls13.rs`) — como o
[`provedor.rs`](../tls/src/provedor.rs) seguiu o exemplo de provedor do
`rustls` para o TLS.

O acesso ao modo QUIC tem três caminhos, todos [B] — a escolha de uma
implementação —, e dois deles com o risco que o projeto evitou ao
escolher o `rustls` ("escrever TLS não diferencia o Duke em nada, e o
`rustls` é uma implementação auditada", `tls/Cargo.toml:5-7`):

1. **(minha)** levar ao `rustls` a API do QUIC sem `std`. Parte da trava
   parece acidental: os buffers que ela usa existem sem `std`, e o que está
   travado neles é o caminho do `io::Read` e, no mesmo bloco, o
   `DeframerVecBuffer::extend` que o `read_hs` chama
   (`rustls-0.23.45/src/msgs/deframer/buffers.rs:196-268`, o `extend` em
   `:257`; `quic.rs:405`), que não usa `std`; o caminho do QUIC não usa o
   bloco travado do `ChunkVecBuffer` (`vecbuf.rs:128`) **(a conferir com
   quem mantém o `rustls`)**;
2. uma cópia do `rustls` com a trava tirada, no repositório — um *fork* de
   uma biblioteca de segurança, para manter a cada versão;
3. escrever o aperto do TLS para o QUIC — o contrário do que o `tls`
   decidiu.

A recomendação **(minha)** é a 1, e esperar por ela.

### A recuperação de perdas e o congestionamento (RFC 9002)

A volta (§5), a perda pela confirmação — por limiar de pacotes e por tempo
— (§6.1), o PTO (§6.2) e o NewReno (§7), com a janela inicial (§7.2) e o
ritmo de envio (§7.7); e, do lado de quem recebe, a confirmação depois de
no máximo dois pacotes que a pedem (RFC 9000 §13.2.2), dentro do atraso
máximo que o cliente anuncia (25 ms por padrão, §18.2). No TCP do Duke,
isso é do `smoltcp`, no kernel; no QUIC, é do programa — código novo, e o
mais delicado: um defeito vira uma enxurrada de retransmissões, e aqui
cada uma é uma decisão do gate e um registro da auditoria.

A recuperação mede o tempo de cada pacote que sai e de cada confirmação
que chega. O programa não tem, pelo gate, esse relógio no ritmo dos
pacotes: é a
[R12-QUIC-RELOGIO](#r12-quic-relogio). E a resolução de hoje, 10 ms, é
grossa para uma bancada de volta abaixo de um milissegundo — a RFC conta
com 1 ms (§6.1.2) —, e as amostras da volta sairiam 0 ou 10 ms: funciona,
mas mal **(minha)**.

### A migração, os IDs de conexão e o 0-RTT

- **Os IDs de conexão** (§5.1) são bytes opacos que cada lado escolhe, e
  pelos quais o servidor acha a conexão. O cliente aceita os do servidor —
  o `NEW_CONNECTION_ID` até o limite que anuncia, o
  `RETIRE_CONNECTION_ID` (§5.1.1, §5.1.2) — e pode usar um ID vazio para
  si, se não reparte a porta entre conexões nem migra: cada associação tem
  a porta dela (`pilha.rs:1048-1067`) **(minha)**. O gate não os vê.
- **A migração** (§9) é só do cliente. No Duke, migrar seria abrir outra
  associação para o mesmo destino, de outra porta local; com um endereço e
  uma placa, não serve para nada. Quando o endereço do Duke muda — o DHCP,
  um NAT no caminho —, o servidor vê um par novo e o valida (§9.3): o
  destino não muda, e o gate não vê.
- **O endereço preferido** (§9.6): o servidor anuncia outro endereço
  depois do aperto; o cliente deveria ir para ele, pode não ir, e fica no
  de antes se a validação falha (§9.6.1). Ignorá-lo cumpre a RFC.
- **O 0-RTT** (RFC 9001 §4.6) pede a retomada — o bilhete que o servidor
  dá, guardado pelo cliente —, que o perfil desliga (`sessao.rs:213`), e
  os dados dele podem ser repetidos por quem os capturou (RFC 9001 §9.2;
  RFC 8446 §8). Fica de fora: [R12-QUIC-0RTT](#r12-quic-0rtt).

### O HTTP/3 (RFC 9114) e o QPACK (RFC 9204)

- **O HTTP/3.** O pedido vai numa corrente bidirecional do cliente, com
  `HEADERS` e `DATA` (§4.1, §7.2); cada lado abre a corrente de controle,
  com o `SETTINGS` primeiro (§6.2.1); os tipos de corrente e de quadro
  desconhecidos são ignorados (§6.2, §9); o servidor não usa o *push* sem
  o `MAX_PUSH_ID` do cliente (§4.6), e o cliente não o manda — como o
  HTTP/2 desliga o *push* no prefácio; o `GOAWAY` (§5.2) e os códigos de
  erro (§8.1). Uma conexão pode servir várias origens (§3.3), e o Duke
  mantém uma por origem, pela regra do HTTP/2. A descoberta (§3.1) é pelo
  `Alt-Svc` ou pela tentativa direta com o ALPN `h3`; o primeiro passo é a
  tentativa direta, como o h2c com conhecimento prévio **(minha)**. Sem o
  UDP, o cliente volta ao TCP (§3.1) — a volta é do programa, e a recusa
  do gate não se esconde nela **(minha)**.
- **O QPACK.** A tabela estática de 99 entradas (apêndice A) e as
  representações de cada linha (§4.5). A tabela dinâmica só existe se
  quem decodifica a anuncia: a capacidade e as correntes bloqueadas
  começam em zero (§5), e com zero nenhum dos dois lados precisa das
  correntes do codificador e do decodificador (§4.2). Um cliente que
  anuncia zero tem um QPACK sem estado — mais simples que o HPACK de hoje,
  que mantém a tabela dinâmica do servidor
  ([`hpack.rs`](../http/src/hpack.rs)).

### O que o kernel e o programa precisariam

- **No kernel**, três coisas: o buffer da associação ([B]) e vários
  datagramas numa decisão ([B], ver [O custo de um datagrama por
  decisão](#o-custo-de-um-datagrama-por-decisão)), que não mudam a
  superfície do gate — nenhum comando novo, nenhuma permissão, nenhum
  tipo de recurso, nenhum prefixo de destino —; e o relógio ([C]), que a
  muda conforme a alternativa: o que um `net.recv` revela, na (a); uma
  chamada fora do gate, na (b); o orçamento do gate, na (c). As conferências do `xtask` que mantêm o HTTP/2 fora do
  kernel e da política (`xtask/src/main.rs:5677-5765`) se estendem ao QUIC
  e ao HTTP/3 **(minha)**.
- **Em `programas`**: um transporte da associação com a taxonomia do
  `conexao` ([B]); e a entrada do HTTP/3 à parte do `conectar` — outra
  função, ou uma opção de compilação —, para o LTO deixar o QUIC fora de
  quem não o chama: escolhido ao conectar, como o HTTP/2, ele entraria no
  `gestor`, a 60 KiB do teto **(minha)**.

## Como encaixa no gate e na política

Hoje, cada envio e cada leitura de rede é uma decisão do gate pelo
destino, no orçamento da taxa ou no do plano de dados. Uma conexão QUIC é
uma sequência de datagramas para um destino, com caminhos que podem
mudar. Para cada coisa que ela faz, a regra de hoje que a cobre:

| O que a conexão QUIC faz | A regra que cobre hoje | Pede decisão? |
|---|---|---|
| Abrir a conexão com o servidor | `net.connect udp:<ip>:<porta>`, pelo destino inteiro na forma normal: a linha `recurso <papel> net.connect …` (`politica/src/arquivo.rs:730-739`), a decisão (`arquivo.rs:1144-1155`), a permissão de alcance enumerado (`politica/src/permissao.rs:701-706`), o comando (`kernel/src/agent/commands.rs:528-542`) | Não. O mesmo servidor no TCP e no UDP são dois destinos (`politica/src/endereco.rs:19-26`): quem quer o HTTP/3 enumera o `udp:` ao lado do `tcp:` |
| Mandar e receber cada datagrama | `net.send` e `net.recv` sobre o número, resolvido no destino para quem pede (`autorizacao.rs:2895-2921`; `conexoes.rs:186-191`), no plano de dados (`autorizacao.rs:2543-2584`) | Não na regra; no custo — [abaixo](#o-custo-de-um-datagrama-por-decisão) |
| Receber só do servidor | o envio ao destino da associação (`pilha.rs:1280`) e o filtro da entrada (`pilha.rs:969-983`): o que a RFC 9000 §9 pede do cliente | Não |
| Continuar depois de uma revogação, de uma contenção, de uma regra do firewall | o pedido seguinte decidido de novo (README.md:2648-2654); o fluxo barrado (`pilha.rs:1270-1274`) e o número cortado ([SEGURANCA, O firewall nativo](SEGURANCA.md#o-firewall-nativo)) | Não. Sem o RST do TCP, o servidor descobre pelo prazo de ociosidade (RFC 9000 §10.1) **(minha)** |
| Acabar com o processo | o coletor derruba a associação (`conexoes.rs:208-243`) | Não |
| Usar IDs de conexão | nada: bytes do protocolo, como as correntes do HTTP/2 | Não |
| O cliente trocar de porta (migração) | uma associação nova para o mesmo destino, decidida pelo gate, no teto do titular (`pilha.rs:117`) | Não — e com um endereço só, não serve |
| O endereço do Duke mudar (DHCP, NAT) | o destino não muda; a associação continua presa à porta local | Não |
| O servidor anunciar outro endereço (§9.6) | um destino novo, só por uma associação nova, decidida pelo gate como o endereço que o DNS dá ([SEGURANCA, O DNS (9.4)](SEGURANCA.md#o-dns-94)) | Não, se o programa segue assim; ignorar é permitido (§9.6.1), e é a recomendação **(minha)** |
| O servidor responder de outro endereço sem anunciar | descartado pelo filtro (`pilha.rs:969-983`), como a RFC 9000 §9 manda | Não |
| O kernel seguir a mudança de caminho sozinho | não existe | **[C]**, e nunca: o destino mudaria sem o gate — [R12-QUIC-CAMINHO](#r12-quic-caminho) |
| Um prefixo `quic:` na política | `endereco.rs:24-26` prevê que "um protocolo novo entra aqui, com o prefixo dele" | **[C]**, e desnecessário: o kernel só vê UDP, e o protocolo é do programa — [R12-QUIC-CAMINHO](#r12-quic-caminho) |
| Juntar duas origens numa conexão (RFC 9114 §3.3) | uma conexão por origem, a regra do HTTP/2 (README.md:4139-4143) | Não: a mesma regra |
| Descobrir o HTTP/3 pelo `Alt-Svc` ou pelo registro HTTPS do DNS | o destino aprendido é decidido pelo gate como o número do DNS | Não **(minha leitura)**; o primeiro passo dispensa os dois |
| Mandar dados no 0-RTT | o perfil: sem retomada, sem 0-RTT (`tls/src/lib.rs:48-49`; `sessao.rs:213`) | **[C]** — [R12-QUIC-0RTT](#r12-quic-0rtt) |
| Medir o tempo de cada pacote | o `system.uptime`: plano de controle, uma ficha por leitura (`commands.rs:316-324`; `autorizacao.rs:2551`); no x86, o `rdtsc` no anel 3, fora do gate, até o endurecimento do #451, que o fechou (`kernel/src/arch/x86_64/mod.rs`, `fechar_os_contadores_ao_usuario`) | **[C]** — [R12-QUIC-RELOGIO](#r12-quic-relogio) |
| Ler ou mandar vários datagramas numa decisão | não existe: um por `net.recv` e um por `net.send` (README.md:2700-2709) | [B], pelo precedente da janela do TCP (`pilha.rs:119-121`), com três condições: o lote decidido antes de mover qualquer datagrama, cada datagrama inteiro, cada um capturado (`captura.rs:38-41`); uma decisão que valesse para os que chegam depois seria cache — [C] |
| Aceitar conexões (o Duke servidor) | não há entrada de rede para programas: o `net.connect` é de saída; só o kernel escuta, o canal do agente e o enlace | [C], e fora do assunto |

### O destino que muda no meio

O dossiê pergunta se a migração e o endereço preferido mudam o destino da
conversa sem o gate, como o *proxy* ([R12-QUIC](DECISOES.md#r12-quic),
[R12-PROXY](DECISOES.md#r12-proxy)). Depende de quem segue a mudança.

**Pelo programa, por uma associação nova: não.** O endereço que o
servidor anuncia é um número na mão do programa, como o que o DNS dá:
para mandar a ele, o programa pede `net.connect` com o destino inteiro, e
o gate o decide como se o número tivesse sido digitado. Fora do alcance,
`DENY_RESOURCE`, e o cliente fica no endereço de antes — o que a RFC
manda quando a validação do caminho falha (§9.6.1). Nenhum datagrama sai
para um destino que o gate não decidiu, e é nisso que o *proxy* é outra
coisa: lá, o destino de verdade vai dentro da conversa, e o gate nunca o
vê. A sessão do TLS segue de um destino ao outro sem aperto novo — o par
do outro endereço prova que é o mesmo pelas chaves da conexão, na
validação do caminho (§8.2) —, e o nome provado vale para os dois; mas o
nome nunca foi recurso da política, e o destino novo foi decidido. Fica
uma coisa a pesar: quem escolhe o endereço é o servidor, que assim faz o
programa sondar qualquer destino que o papel alcança — a forja de pedidos
pelo endereço preferido (RFC 9000 §21.5.3) —, limitada à lista enumerada
da política. Por isso a recomendação **(minha)** é ignorar o endereço
preferido, o que a RFC deixa.

**Pelo kernel, sozinho: sim, e é [C].** Uma associação que passasse a
aceitar ou a mandar para o endereço novo, ou um recurso "conexão QUIC"
pelo ID em vez do destino, faria o destino mudar sem o gate — a mesma
razão por que o dossiê recomenda nunca a alternativa (a) do *proxy*. Não
se propõe.

O lado do cliente, que é o único do Duke, nem precisa da mudança: a RFC
só deixa o cliente iniciar uma migração, e manda descartar o que vem de um
endereço de servidor desconhecido (§9) — o filtro que a associação já
tem, e que as mutações do UDP conferem.

### O custo de um datagrama por decisão

As contas abaixo são **(minhas, a medir)**, com as medidas do README como
régua:

- **Um MiB pelo QUIC, sem lote.** Com uns 1420 bytes de dados por
  datagrama de 1472 — o cabeçalho curto, o quadro e a etiqueta levam o
  resto —, são uns 740 datagramas. Cada `net.recv` traz um: 740 decisões,
  e o dobro quando a leitura espera, porque a que espera custa duas — a
  que suspende e a da entrega (README.md:2782-2784). O cliente confirma
  a cada dois pacotes (RFC 9000 §13.2.2): uns 370 `net.send`. São de
  1100 a 1850 decisões por MiB, contra perto de 85 pelo TCP
  (README.md:3417-3418): de 13 a 22 vezes.
- **O tempo do gate.** De 280 a 465 µs por decisão (README.md:3189-3190,
  3524) dão de 0,3 a 0,9 s de gate por MiB.
- **A auditoria.** Um registro por decisão. A 1 MiB/s, o QUIC escreveria
  de duas a três vezes e meia o que o NSF lê (512 por segundo), e o NSF se
  declararia degradado (`audit-gap`); a contrapressão do caminho seguraria
  o volume, com o journal no ritmo dele (`oleoduto.rs:71-81`) — e cada
  espera dela é, para o congestionamento do QUIC, uma volta mais longa.
- **Com o lote.** Se um `net.recv` levasse até 16 KiB de datagramas numa
  decisão — uns onze —, e o cliente confirmasse uma vez por lote, seriam
  uns 65 `net.recv` (130 com as esperas) e uns 65 `net.send`: de 130 a
  195 decisões por MiB, de uma vez e meia a duas vezes e pouco o TCP.

O lote é [B] pelo precedente: a janela do TCP fez um `net.recv` levar
vários segmentos numa decisão ([A janela do
TCP](../README.md#a-janela-do-tcp)), sem mudar quem decide, o que se
autoriza, nem a regra de um registro por decisão. O que muda é a unidade
de uma leitura UDP — hoje "um datagrama inteiro, ou nenhum" — e por isso
ele entraria como um parâmetro opcional, com a leitura de hoje como
padrão. O coordenador o classificou como [B]: um registro da auditoria
diz quem pediu, o método, o destino, o código e o resumo dos parâmetros
(`politica/src/auditoria.rs:421-439`), e nenhum campo diz quantos bytes,
segmentos ou datagramas a operação moveu — o lote não muda o que um
registro afirma, nem a regra de um registro por decisão; muda o volume
por registro, como a janela do TCP já muda. Fica [B] com três condições:
o lote decidido antes de mover qualquer datagrama; cada datagrama
inteiro; cada datagrama capturado pelo `net.observe`, com o número do
registro (`kernel/src/rede/captura.rs:38-41`). Uma decisão que valesse
para os datagramas que chegam depois dela seria cache, e o gate é sem
cache: isso seria [C].

### O que não muda

- **Nenhuma autoridade nova.** A conexão QUIC, as correntes, os IDs e as
  chaves são estado do protocolo, no processo; o gate não os vê, como não
  vê as correntes do HTTP/2. O certificado prova um nome ao programa e
  não autoriza nada; o destino é o recurso.
- **O NSF vê o que vê de qualquer conexão:** as decisões do gate sobre a
  associação, e nada de dentro. A captura do `net.observe` é só de UDP e
  só dos destinos que um papel tem nela ([SEGURANCA, Limitações
  deliberadas](SEGURANCA.md#limitações-deliberadas)): um destino QUIC
  observado encheria o anel de texto cifrado **(minha)**.
- **Nenhuma ABI de fora, nenhum segundo gate, nenhuma segunda política:**
  o QUIC é um protocolo do programa, como o DNS, o TLS e o HTTP ([SEGURANCA,
  As decisões consolidadas](SEGURANCA.md#as-decisões-consolidadas)).

## A necessidade

### Quem fala HTTP no Duke

- **Os programas da bancada** — `pagina`, `buscador`, `correntes`,
  `compressao`, `cookies`, `vazao`, `validade` —, contra os servidores do
  hospedeiro: o [`http.py`](../xtask/bancada/http.py), HTTP/1.1, claro e
  atrás do TLS, e o [`http2.py`](../xtask/bancada/http2.py), HTTP/2.
- **Os programas do IC** — `icp`, `consulta`, `livro`, `verificado`,
  `carteira`, `implantacao`, `gestor` —, todos pelo HTTP/1.1
  (`programas/src/icp.rs:596`; o do `consulta`,
  `programas/src/bin/consulta.rs:40`). O grupo C deixa o HTTP/3 e o QUIC de fora
  para o IC: "nada disso tem uma necessidade demonstrada"
  ([OPERACAO, grupo C](OPERACAO.md#o-que-fica-de-fora-de-propósito-grupo-c);
  [DECISOES, as fechadas](DECISOES.md#as-fechadas-que-não-se-reabrem)).
- **O `instalador`**, que traz o código selado pela rede.

O resto da rede não é HTTP: o DNS e o Roughtime, pelo UDP; o canal do
agente, pelo TCP na 7070; e o enlace entre Dukes, pelo TCP na 7071, com o
Noise IK — decisões fechadas ([ENLACE, As decisões](ENLACE.md#as-decisões)),
que o QUIC não reabriria sem uma proposta própria.

### O que o HTTP/3 traria, e o que o HTTP/2 já cobre

| O que o HTTP/3 traz | Na bancada do Duke | Fora dela |
|---|---|---|
| Várias correntes numa conexão | o HTTP/2 já faz: oito correntes de 1 byte a 100 KiB acabam juntas em 110 a 220 ms, e a lenta não segura as outras (README.md:4074-4077) | o mesmo |
| A cabeça comprimida | o HPACK | o QPACK — o mesmo ganho |
| A perda de um pacote sem segurar as outras correntes | a bancada não perde pacote: é o laço do emulador | só numa rede com perda |
| Uma volta a menos para abrir a conexão | a bancada responde em meio milissegundo (README.md:4070-4071), e o aperto do TLS custa de 100 a 170 ms por conexão, no hóspede, no emulador sem aceleração (README.md:3180-3183): uma volta a menos não se vê | de 20 a 100 ms por conexão nova **(minha)** |
| A migração | não se usa: um endereço | aparelhos que trocam de rede |
| O 0-RTT | de fora | de fora |

E o que o HTTP/2 mediu diz onde está o custo: "O que se mede é o
hóspede" — a bancada responde em meio milissegundo, e o custo de cada
pedido é o caminho dele no Duke, um `net.send` e um `net.recv`, cada um
uma decisão do gate, a espera e a cópia (README.md:4070-4073). O QUIC
acrescenta decisões justamente a esse caminho.

Um servidor de HTTP/3 de verdade fala também HTTP/1.1 e HTTP/2 pelo TCP:
a descoberta pelo `Alt-Svc` chega numa resposta pelo TCP, e a RFC
recomenda ao cliente voltar ao TCP quando o UDP não passa (RFC 9114
§3.1). Um servidor
só de HTTP/3 é a exceção **(minha leitura)**.

### A resposta franca

**Adiar.** Nenhum consumidor do Duke ganha com o HTTP/3, e o que ele custa
é grande e certo: um transporte inteiro no processo, uma decisão [C]
sobre o relógio, mais decisões e registros por byte, programas maiores, e
uma dependência que o `rustls` ainda não dá sem `std`. Não fazer de vez
também não é a resposta: a conexão cabe no gate de hoje, o relógio pede
a [R12-QUIC-RELOGIO](#r12-quic-relogio), e esta avaliação fica como o
mapa para quando a necessidade vier.

### O que mudaria a resposta

- **Um consumidor com necessidade demonstrada:** um servidor que o Duke
  precise alcançar e que só fale HTTP/3, ou um protocolo que só existe
  sobre o QUIC (o DNS sobre QUIC, RFC 9250; o WebTransport) — cada um uma
  proposta própria.
- **Uma medida numa rede de verdade** em que o HTTP/2 perca para o
  bloqueio do TCP na perda, ou para a volta a mais do aperto — com a perda
  e a latência que a bancada não tem.
- **O relógio decidido por outro motivo.** O README já registra a falta
  dele nos cookies — "um relógio que o programa lesse sem uma decisão do
  gate, ou a leitura dele no orçamento do plano de dados, seria uma
  abstração nova, e não entrou" (README.md:3926-3943) —, ali o civil; o
  QUIC precisa do monotônico. Uma decisão sobre o relógio do programa
  tiraria do caminho a única [C] dele.
- **O lote do UDP feito por outro motivo**, e **o `rustls` com o QUIC sem
  `std`**: cada um tira um trabalho do caminho.
- **A [R12-SIMD](DECISOES.md#r12-simd) aprovada:** barateia a cifra por
  pacote — pouco, diante do custo das decisões.

## O tamanho e o risco

### O trabalho, por parte

Em incrementos do tamanho do HTTP/2 — o pacote, os testes no hospedeiro
contra o `nghttpd`, a bancada, o programa, a suíte, a fumaça e as
mutações —, todos **(minha estimativa)**:

| Parte | O que entrega | Código | Em HTTP/2 | Pede |
|---|---|---|---|---|
| O UDP do plano de dados | o buffer da associação e o lote, com a suíte e as mutações deles | 150–400 | 0,2–0,4 | [B] |
| O relógio | o que a decisão disser | 50–150 | 0,1 | [C], [R12-QUIC-RELOGIO](#r12-quic-relogio) |
| O TLS no QUIC | o modo QUIC sem `std`, o `quic::Algorithm`, o aperto por nível | 400–700, mais o `rustls` | 0,4–0,7 | [B] |
| O transporte | a RFC 9000, o cliente, um caminho | 2 700–3 600 | 1,2–1,6 | [B] |
| A recuperação | a RFC 9002 | 700–1 000 | 0,3–0,5 | [B] |
| O HTTP/3 e o QPACK | as RFCs 9114 e 9204, o QPACK sem tabela dinâmica | 1 300–1 900 | 0,6–0,8 | [B] |
| O programa e a bancada | o transporte da associação, o `conectar` à parte, o programa, o servidor de referência, o retransmissor que perde, a fumaça e as medidas | 300–600, mais a bancada | 0,5–0,8 | [B] |
| **Soma** | | **5 600–8 350** | **3,3–4,9** | uma [C] |

Os testes seriam tantos quanto o código, ou mais — a régua do HTTP/2:
3 154 linhas de teste para 2 642 de código —: a recuperação de perdas
só se confere com perdas de verdade, e de propósito.

### Os riscos

- **A superfície nova é do processo, e grande.** Um leitor de datagramas
  hostis, uma máquina de estados de transporte, a remontagem das correntes
  fora de ordem. As chaves do Initial saem de um ID que viaja em claro: a
  cifra dele não protege contra quem vê o caminho (RFC 9001 §5.2), e quem
  vê o caminho pode estragar o aperto — negação, e não quebra: o aperto
  ainda é autenticado pelo TLS. Cada coisa que o par faz crescer precisa
  de teto, como no HTTP/2 (RFC 9000 §21.7, §21.9).
- **A recuperação vira volume de auditoria.** Um defeito que retransmite
  demais é, aqui, uma enxurrada de decisões e de registros. A
  contrapressão do caminho a segura; o NSF fica para trás. E o UEBA acusa
  uma taxa de pedidos de 4 vezes a da base de cada identidade
  (`seguranca/src/ueba.rs:14-15`, `:55`): o QUIC sem o lote põe o programa
  no incomum — contexto para o NSF, e não contenção.
- **A cifra por pacote.** O ChaCha20-Poly1305 faz uns 25 blocos para um
  datagrama de 1445 bytes de texto — o texto, a chave do Poly1305 e a
  máscara do cabeçalho —, contra 257 para um registro de 16 KiB: uns 10% a
  mais por byte **(minha conta)**. O AES-128-GCM em software, 104 MiB/s no
  hospedeiro, entra em toda conexão, no Initial. No hóspede, o TLS já
  custa perto de metade da vazão — 1119–1402 KiB/s cifrados, contra
  2320–2445 claros (README.md:3519-3520) —, e o QUIC soma isso ao custo
  das decisões. A [R12-SIMD](DECISOES.md#r12-simd) ajudaria, e não é
  condição.
- **A dependência.** O modo QUIC do `rustls` sem `std`: esperar a
  mudança na origem, ou manter uma cópia — e, na cópia, o perfil e a
  proibição do `dangerous()` precisam valer como valem hoje.
- **O tamanho dos programas.** Por proporção ao HTTP/2 — de 40 a 50 KiB
  para 2 642 linhas —, as 5 400 a 7 800 linhas que iriam ao programa (o
  transporte, o TLS, a recuperação, o HTTP/3 com o QPACK e o programa)
  acrescentariam de 80 a 150 KiB a um programa no x86, mais o que o modo
  QUIC do `rustls` traz **(minha, a medir)**. O `correntes` caberia (682
  KiB hoje); o `gestor`, a 60 KiB do teto, não; o `implantacao`, a
  `carteira`, o `icp` e o `verificado`, de 85,4% a 89,8%, iriam a 93–98%
  com 80 KiB e passariam do teto com 150 — o `livro` ficaria a 98% —; por
  isso o HTTP/3 só pode entrar em quem o chama.
- **O relógio de 10 ms**, grosso para a volta da bancada: retransmissões à
  toa, e uma volta medida que não é a de verdade **(minha)**.
- **O buffer de 4 KiB**: perdas a cada rajada, até ele crescer. E quem
  adivinha a porta local — a seguinte de uma faixa (`pilha.rs:140-142`,
  `:1051-1058`) — induz perdas: o filtro só tira o datagrama alheio que
  está na frente da fila; atrás de um do destino ainda não lido, o alheio
  ocupa vaga (`pilha.rs:966-968`), e cada perda corta a janela do
  servidor.
- **A bancada não perde pacote.** O laço do emulador não perde nem
  reordena: sem um retransmissor que perca de propósito, a recuperação
  iria para a imagem sem teste.
- **O emulador e o UDP.** O `guestfwd` da rede do emulador é de TCP **(minha
  leitura do emulador)**: o servidor de HTTP/3 da bancada tem de ser um
  servidor UDP do hospedeiro, alcançado por `10.0.2.2`, como as fontes de
  Roughtime da bancada de tempo (`xtask/src/servidor_de_hora.rs:7`, e a
  linha `recurso tempo net.connect udp:10.0.2.2:5319 …`,
  `politica/src/lib.rs:402`) — o caminho que o Roughtime já prova.

### As bancadas que validariam

- **Um servidor de referência**, como o `nghttpd` é para o HTTP/2 — que a
  CI instala (`.github/workflows/ci.yml:87-93`): uma implementação
  inteira e independente do QUIC e do HTTP/3. Candidatos **(minha, a
  conferir: o pacote na CI e a versão fixada)**: o `aioquic`, em Python —
  a língua dos scripts da bancada —, com QUIC e HTTP/3 próprios; os
  exemplos do `ngtcp2` e do `nghttp3`, em C, do autor da nghttp2 — o par
  do `nghttpd`. Para os testes do pacote no hospedeiro, um servidor em
  Rust (o `quinn` com o `h3`) sobre o `rustls` com o *ring*, como os testes
  do TLS fazem hoje; mas é a mesma máquina do TLS dos dois lados, e não
  substitui os outros dois.
- **Na máquina**, o servidor UDP do hospedeiro em `127.0.0.1:<porta>`,
  alcançado por `udp:10.0.2.2:<porta>`, com o destino na política da
  imagem de desenvolvimento — uma mudança [B], como a de cada bancada. As
  rotas do `http2.py` — várias correntes, o corpo grande, o `GOAWAY`, as
  respostas malformadas, a corrente reiniciada — e as do QUIC: o Retry, a
  negociação de versão, o reset sem estado, a troca de chave, o servidor
  respondendo de outra porta (descartado e contado em
  `foreign_datagrams_dropped`) e o endereço preferido (ignorado).
- **O retransmissor que perde**: um repetidor UDP no hospedeiro que perde,
  duplica, reordena e atrasa, com semente fixa — como o *proxy* que mente
  da bancada do IC ([`icp.py`](../xtask/bancada/icp.py)) —; e, nos testes
  do pacote, uma rede na memória, como o servidor de mentira do HTTP/2.
- **As medidas**: as decisões por MiB, contra as 85 do TCP; a vazão clara e
  cifrada, contra o HTTP/2 do `correntes` (40 pedidos de 1 KiB,
  README.md:4065-4068); o aperto, contra os 100 a 170 ms do TLS; o NSF sem
  `audit-gap`; o pico do heap; o tamanho dos programas nas duas
  arquiteturas.
- **As mutações**: as do kernel, como as do UDP; as do pacote — a proteção
  do cabeçalho desligada, o número do pacote reconstruído com um a menos,
  as faixas da confirmação, o PTO que não se arma, o controle de fluxo e o
  teto de correntes que não se conferem, o limite de IDs, o índice do QPACK
  com um a mais, o quadro do HTTP/3 na corrente errada —; e as que já
  existem, do filtro da associação.
- **As duas arquiteturas, em debug e em release**, e a fumaça com uma
  perna do HTTP/3, como a do HTTP/2 (`xtask/src/main.rs:16784-17070`).

## A recomendação

**Adiar o HTTP/3 e o QUIC (minha).** Não há consumidor, e o caminho custa uma
decisão [C], três trabalhos [B] no kernel e no TLS, e de três a cinco
incrementos do tamanho do HTTP/2 **(minha)**. O que esta avaliação deixa
fechado para quando a necessidade vier: a conexão cabe no gate de hoje —
só o cliente, um caminho, sem migração, sem endereço preferido, sem 0-RTT,
uma conexão por origem, o HTTP/3 só em quem o chama —, e o relógio pede a
[R12-QUIC-RELOGIO](#r12-quic-relogio).

### Os incrementos, se for fazer

Na ordem das dependências; o 1 e o 2 podem correr juntos, e o 3 ao lado
deles:

| Incremento | O que entrega | Pede |
|---|---|---|
| 1. O UDP do plano de dados | o buffer da associação no tamanho do TCP — o pior caso do heap não muda, porque a tabela é a mesma —; o lote de datagramas numa decisão, opcional; a suíte, as mutações, a medida de decisões por MiB | [B] |
| 2. O relógio | o que a decisão disser | [C]: [R12-QUIC-RELOGIO](#r12-quic-relogio) |
| 3. O TLS no QUIC | o modo QUIC do `rustls` sem `std`; o `quic::Algorithm` das três suítes; os vetores do apêndice A da RFC 9001 | [B] |
| 4. O transporte e a recuperação | a RFC 9000 e a RFC 9002, cliente, um caminho, versão 1; testes contra o servidor de referência e contra a rede na memória que perde | [B]; depende do 1, do 2 e do 3 |
| 5. O HTTP/3 e o QPACK | as RFCs 9114 e 9204, o QPACK sem tabela dinâmica, a conferência da cabeça com o HTTP/2 | [B]; pode começar sobre um transporte de mentira |
| 6. O programa, a bancada e a fumaça | o transporte da associação, a entrada à parte, o programa, o servidor e o retransmissor da bancada, as medidas | [B] |
| Depois, só com necessidade | o `Alt-Svc`; o endereço preferido pelo gate; o 0-RTT; o servidor | [B]; [B]; [C], [R12-QUIC-0RTT](#r12-quic-0rtt); [C], proposta própria |

### As decisões [C]

No formato curto do dossiê, para irem ao [`DECISOES.md`](DECISOES.md)
quando a R12-QUIC for revista. Só a primeira está no caminho; as outras
existem se alguém as quiser, e a recomendação delas é não.

#### R12-QUIC-RELOGIO

**O relógio do programa no ritmo dos pacotes.**

- **O problema.** A recuperação do QUIC (RFC 9002 §5, §6) mede o tempo de
  cada pacote que sai e de cada confirmação que chega, e arma prazos de
  milissegundos. O relógio de um programa é o `system.uptime`: uma decisão
  do gate no plano de controle, que gasta uma ficha da taxa do papel a
  cada leitura (`kernel/src/agent/commands.rs:316-324`;
  `kernel/src/autorizacao.rs:2551`), e anda de 10 em 10 ms
  (`programas/src/nativo.rs:236-238`). No ritmo dos pacotes, a taxa do
  operador — 50 por segundo, rajada de 100 (`politica/src/lib.rs:398`) —
  acaba em segundos, e com ela os outros pedidos de controle dos programas
  da mesma sessão: o experimento dos cookies o mostrou com o relógio civil
  (README.md:3926-3943). E havia um relógio fora do gate que o desenho não
  previu: o kernel x86 não ligava o `CR4.TSD` — o `CR4` só ganhava o SMEP
  —, e o `rdtsc` rodava no anel 3: o contador de ciclos, sem decisão nem
  registro, numa frequência que o programa só sabe calibrando contra o
  `system.uptime`. Nenhum dos programas o usava, e nenhuma conferência o
  proibia. No ARM, o kernel não escrevia o `CNTKCTL_EL1`, e a leitura do
  `CNTVCT_EL0` no EL0 dependia do firmware. O endurecimento [B] do #451,
  no lote B do #448, fechou essa porta, sem esperar esta decisão: o
  `CR4.TSD` ligado e o `CR4.PCE` desligado em cada núcleo
  (`kernel/src/arch/x86_64/mod.rs`, `fechar_os_contadores_ao_usuario`,
  chamada de `usuario::ligar_neste_nucleo`); no ARM, o `CNTKCTL_EL1` e o
  `PMUSERENR_EL0` em zero em cada núcleo
  (`kernel/src/arch/aarch64/usuario.rs`, `fechar_os_contadores_neste_nucleo`,
  no `init` e em `smp::entrada_secundaria`). Conferido no QEMU com o TCG:
  o processo que lê o contador morre pela falha de proteção — no x86, o
  #GP; no ARM, a exceção síncrona, com o ESR da leitura do `CNTVCT_EL0` —,
  em cada núcleo. A resolução do relógio que o programa ganha é parte
  desta decisão: um relógio de ciclos é a régua de um ataque de tempo
  **(minha)**.
- **A área de 5.3.** O Gate e a autorização: o que uma permissão revela,
  na (a); uma chamada fora do gate, na (b); o orçamento do gate, na (c).
- **As alternativas.** (a) **(minha)** O instante no resultado do plano de
  dados: o `net.recv` e o `net.send` de uma associação dizem o instante do
  monotônico em que a pilha recebeu o datagrama, ou o pôs na fila de
  saída. Nenhuma decisão nem registro a mais, e o instante é de um recurso
  de quem pede, decidido pelo mesmo gate; mas revela o monotônico a quem
  tem `net.connect` sem `system.read` — na política padrão, os papéis
  `tempo` e `enlace` (`politica/src/lib.rs:401`, `:417`), serviços do
  kernel. O `smoltcp` 0.14 não carimba o datagrama — o `UdpMetadata` só
  tem o par, o endereço local e o `PacketMeta`
  (`smoltcp-0.14.0/src/socket/udp.rs:16-27`) —: o instante seria o da
  volta da pilha, guardado pelo kernel **(a conferir)**. Há precedente de carimbo num resultado de rede, mas do lógico,
  de um segundo: o `ts_ms` do `net.observe` (`commands.rs:8700`;
  `kernel/src/rede/captura.rs:81`). (b) Uma chamada de mecanismo do
  relógio, sem o gate — a "abstração nova" que o README descreve: cresce
  a lista `chamada` do contrato v2 ([DS-2](SDK.md#o-contrato-v2-ds-2)) e
  dá o relógio a todo processo, sem decisão nem registro — o que o
  `rdtsc` dava, no x86, até o endurecimento. (c) A leitura do
  `system.uptime` no orçamento do plano de dados — a outra "abstração
  nova": o plano de dados deixa de ser só a operação sobre um recurso
  aberto (`kernel/src/agent/registry.rs:166-191`). (d) Nada: sem relógio, a
  recuperação não mede a volta — o prazo de um `wait` arma os
  temporizadores, mas não mede a volta de um pacote —, e fica presa à
  volta inicial da RFC 9002 (333 ms, §6.2.2): o QUIC anda, às cegas
  **(minha)**.
- **A recomendação provisória (minha).** (d), enquanto o HTTP/3 estiver
  adiado; com a necessidade, (a), só na associação UDP — o instante vem
  com a decisão que já acontece, e é sobre o recurso de quem pede. A
  resolução — o tique de 10 ms, ou a régua dos ciclos — entra na decisão.
- **As fechadas.** O DS-2: crescer o contrato é decisão revisada. "Nenhuma
  decisão de autorização lê o civil nem o lógico" ([O
  tempo](../README.md#o-tempo)) — e nenhuma das alternativas muda isso: o
  instante sai da decisão, não entra nela. O gate sem cache, decidido pela
  medida.
- **Destrava.** O QUIC; e os prazos de qualquer programa que meça o tempo.
  Não os cookies, que precisam do civil.

#### R12-QUIC-0RTT

**Os dados antecipados e a retomada.**

- **O problema.** O 0-RTT manda dados no primeiro voo, com a chave de uma
  sessão anterior: exige guardar o bilhete da retomada que o servidor dá,
  e aceitar que os dados se repitam — quem os capturou os reapresenta ao
  servidor (RFC 9001 §9.2; RFC 8446 §8). E a sessão retomada não confere de
  novo a cadeia nem a validade do certificado. O perfil do TLS não tem
  nenhum dos dois (`tls/src/lib.rs:48-49`; `tls/src/sessao.rs:213`).
- **As alternativas.** (a) Nada: o perfil de hoje. (b) **(minha)** A
  retomada sem o 0-RTT, com o bilhete na memória do processo, como o pote
  de cookies. (c) A retomada e o 0-RTT, só para os pedidos seguros (RFC
  8470). Guardar o bilhete além do processo seria custódia de um segredo
  — outra decisão.
- **A área de 5.3.** Semântica de segurança nova: dados que se repetem,
  e a retomada sem reconferir o certificado; custódia, se o bilhete
  passar do processo.
- **A recomendação provisória (minha).** (a): o QUIC funciona inteiro sem
  os dois.
- **As fechadas.** O certificado prova um nome ao programa e não autoriza
  nada ([SEGURANCA](SEGURANCA.md#as-decisões-consolidadas)); a custódia
  das chaves, nenhuma exportada
  ([1.7](../CLAUDE.md#17-as-invariantes-permanentes)).
- **Destrava.** Uma volta a menos na conexão repetida — nada que a
  bancada meça.

#### R12-QUIC-CAMINHO

**A mudança de caminho seguida pelo kernel.**

- **O problema.** Uma conexão QUIC pode mudar de caminho — o cliente
  migra, o servidor anuncia outro endereço (RFC 9000 §9, §9.6) —, e o
  destino é o recurso da política. Seguida pelo programa, por uma
  associação nova que o gate decide, a mudança cabe no modelo de hoje ([O
  destino que muda no meio](#o-destino-que-muda-no-meio)). A decisão só
  existe se o kernel a segue sozinho.
- **As alternativas.** (a) O programa segue, por `net.connect`: nada muda
  no gate. (b) **(minha)** A associação aceita e manda para o endereço que
  a conexão validou, sem `net.connect`: o destino muda sem o gate. (c)
  **(minha)** Um recurso "conexão QUIC", pelo ID, com um prefixo `quic:`
  na política (`politica/src/endereco.rs:24-26`): o QUIC no kernel.
- **A área de 5.3.** O Gate: um destino que muda sem ele, na (b); um
  tipo de recurso novo, na (c).
- **A recomendação provisória (minha).** Nenhuma mudança de caminho, e o
  endereço preferido ignorado; a (a) só com uma necessidade, e é [B]. Nunca
  a (b), que é a alternativa (a) do *proxy*; nem a (c), porque o protocolo
  é do programa.
- **As fechadas.** As decisões consolidadas
  ([SEGURANCA](SEGURANCA.md#as-decisões-consolidadas)): o gate decide o
  destino, e o protocolo é do programa. A
  [R12-PROXY](DECISOES.md#r12-proxy) recomenda nunca tirar o destino da
  decisão.
- **Destrava.** Nada que o Duke use: uma máquina com um endereço não
  migra.

O Duke como servidor de HTTP/3 — ou de qualquer coisa, para um programa —
não entra aqui: o `net.connect` é de saída, e só o kernel escuta, na 7070
e na 7071. Abrir a escuta a um programa seria uma proposta própria, [C],
sem consumidor no roteiro.

### O que não espera

Nada do QUIC precisa começar agora. Dois trabalhos [B] independentes, se
o coordenador quiser:

- **(minha)** medir o custo de um datagrama por decisão com o UDP de
  hoje — um eco UDP na bancada —, para a próxima revisão da R12-QUIC ter
  o número em vez da conta;
- acertar o que resta da seção seguinte: o `DENY_RATE` do README e o
  tamanho do `correntes`.

### As fechadas que esta avaliação respeita

- **As invariantes** ([1.7](../CLAUDE.md#17-as-invariantes-permanentes)):
  um gate, uma política, uma cadeia de autoridade; nenhum `ALLOW(*)`;
  nenhuma ABI de fora.
- **As decisões consolidadas do tecido**
  ([SEGURANCA](SEGURANCA.md#as-decisões-consolidadas)): o DNS, o TLS e o
  HTTP são programas, e o gate decide o destino — o QUIC e o HTTP/3
  também seriam.
- **O grupo C** ([OPERACAO](OPERACAO.md#o-que-fica-de-fora-de-propósito-grupo-c)):
  nada de HTTP/3 nem de QUIC para o IC; e o IPv6, de fora — o QUIC daqui
  seria só IPv4.
- **D1 a D10 e a porta 7071 do enlace** ([ENLACE](ENLACE.md#as-decisões)):
  o QUIC não se propõe para o enlace nem para a malha.
- **O DS-2** ([SDK](SDK.md#o-contrato-v2-ds-2)): a forma binária dos
  programas não muda, e o contrato só cresce por decisão revisada.
- **O gate sem cache** ([README](../README.md#o-gate-sem-cache)): o lote
  não guarda decisão; cada pedido é decidido.

## As incoerências achadas nas fontes

- **`DENY_RATE` não existe.** O README (README.md:3936), o
  [SEGURANCA](SEGURANCA.md#o-http-fase-12) (`docs/SEGURANCA.md:553`) e um
  comentário do `programas/src/nativo.rs:65` diziam, no `f19df2d`, que a
  taxa esgotada recusa com `DENY_RATE`; o código da política é
  `RATE_LIMIT` (`politica/src/codigo.rs:58`), e é o que a auditoria, o
  gate e o resto do README dizem. O SEGURANCA e o comentário foram
  acertados no `5d2f4fb`; o README vai com o incremento do kernel em
  curso.
- **O tamanho do `correntes` envelheceu.** O README diz que ele "tem 761
  KiB no x86 e 771 KiB no ARM" (README.md:4162-4163); a proveniência do
  commit `f19df2d` diz 698 576 bytes (682 KiB) e 614 928 (600 KiB). A
  medida é de 15/10 (`d9f0280`), antes de os programas perderem a tabela
  de símbolos — "um sexto de cada programa" (`3dc0c5d`, 21/10) —, dos
  pacotes de protocolo em `opt-level = "z"` (`7a81916`, 26/10) e da
  promoção do compilador (`c87a65a`, 16/11); o texto a dá no presente.
- **A recomendação provisória da R12-QUIC não vê três custos.** "O QUIC
  sem migração e sem 0-RTT, se ele couber no destino decidido"
  ([R12-QUIC](DECISOES.md#r12-quic)) — cabe; mas o caminho pede também o
  relógio ([C]), o lote e o buffer da associação ([B]) e o `rustls` sem
  `std` ([B]). Não é contradição: é o que a avaliação acrescenta, para a
  entrada ser revista com ela.
