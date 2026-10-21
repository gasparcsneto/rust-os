# Código de terceiros

O Duke é licenciado sob MIT OU Apache-2.0, a critério de quem usa. As partes
listadas aqui vieram de outros projetos e seguem sob a licença de origem, com
o aviso de copyright que ela exige.

## Redox OS — `redox-os/drivers`

A pilha gráfica em `kernel/src/grafico/` segue o desenho dos drivers gráficos
do Redox, e cinco arquivos são porte de código deles:

| Arquivo do Duke | Origem no Redox |
|---|---|
| `kernel/src/grafico/mod.rs` — o trait `AdaptadorGrafico` | `graphics/driver-graphics/src/lib.rs` — `GraphicsAdapter` |
| `kernel/src/grafico/dano.rs` — `Dano` | `graphics/graphics-ipc/src/common.rs` — `Damage` |
| `kernel/src/grafico/linear.rs` — `AdaptadorLinear` | `graphics/vesad/src/scheme.rs` — `GraphicScreen::sync` |
| `kernel/src/virtio/gpu.rs` — as estruturas do protocolo e os comandos | `graphics/virtio-gpud/src/main.rs` — as estruturas; `graphics/virtio-gpud/src/scheme.rs` — `create_dumb_framebuffer`, `update_plane` |
| `kernel/src/grafico/virtio.rs` — `AdaptadorVirtio` | `graphics/virtio-gpud/src/scheme.rs` — `VirtGpuAdapter` como `GraphicsAdapter` |

Obtido do espelho em <https://github.com/redox-os/drivers>, no commit
`20ffe4d7f4a85b7cc1f59495d7e6e355fed4cb06`, de 2025-11-29 — o último antes de o
repositório ser arquivado, em abril de 2026. O original fica em
<https://gitlab.redox-os.org/redox-os/drivers>. Arquivado quer dizer que
correções feitas lá depois não chegam aqui sozinhas.

O porte não é literal, e cada arquivo diz no cabeçalho o que mudou e por quê.
Um dos motivos vale registrar aqui, porque é um defeito do original: o recorte
de `Damage::clip` soma `x + width` em `u32` sem conferência, e com `x` perto do
fim do tipo a soma dá a volta e o retângulo "recortado" sai da tela.
Compilado e medido com o código deles: um dano em `x = u32::MAX - 1` de
largura 10, numa tela de 1280, sai como `x = 1280, largura = 10`. O `vesad`
copia o que o recorte devolve, e isso é escrita além do fim de cada linha. O
porte satura a soma, e a suíte reprova a lógica original.

O `virtio-gpud` tem dois comportamentos que o porte não trouxe, e o
cabeçalho de `kernel/src/virtio/gpu.rs` diz por quê. O `update_plane`
transfere o quadro inteiro ao dispositivo a cada atualização, qualquer que
seja o dano recebido — e descarrega o dano recortado pelo `Damage::clip`
acima. E cada resposta do dispositivo é conferida com `assert_eq!`: uma
recusa derruba o daemon, o que num kernel seria derrubar a máquina. Aqui só o
dano atravessa, e uma recusa é um erro devolvido a quem pediu. A suíte
reprova a transferência do quadro inteiro, e a recusa conferida.

```text
MIT License

Copyright (c) 2017 Redox OS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## rustls — o exemplo de provedor

O provedor de criptografia do pacote `tls` segue a estrutura do exemplo de
provedor do próprio `rustls`, que mostra como ligar os traits dele às
primitivas do RustCrypto e do dalek:

| Arquivo do Duke | Origem no `rustls` |
|---|---|
| `tls/src/cifra.rs` — a cifra de um registro do TLS 1.3 | `provider-example/src/aead.rs` — `Tls13Cipher` |
| `tls/src/resumo.rs` — o resumo e o HMAC | `provider-example/src/hash.rs` e `hmac.rs` |
| `tls/src/troca.rs` — a troca X25519 | `provider-example/src/kx.rs` |
| `tls/src/provedor.rs` — o `CryptoProvider` montado | `provider-example/src/lib.rs` — `provider()` |

Obtido de <https://github.com/rustls/rustls>, na tag `v/0.23.31`, como
referência para os traits da série 0.23; o `rustls` usado é o 0.23.45.

Não é cópia literal: o que muda, e por quê, está no cabeçalho de cada
arquivo. O exemplo traz o TLS 1.2 e sorteia pelo sistema operacional; aqui é
só TLS 1.3, a cifra é uma implementação genérica para as três suítes, o
acaso é o gerador semeado por quem conecta — que falha fechado sem semente
—, a troca X25519 recusa o ponto que não contribui (o exemplo aceita) e há
também P-256, e a verificação de assinatura é própria: ECDSA P-256 e
P-384, Ed25519 estrito e RSA — o perfil das cadeias das autoridades
públicas, com a chave conferida —, e nada além.

```text
Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

## Roughenough — os vetores de teste do Roughtime

Quatro arquivos de dados em `hora/testdata/`, e nenhuma linha de código:

| Arquivo do Duke | Origem no Roughenough |
|---|---|
| `hora/testdata/rfc10049-pedido.104172a3` | `testdata/rfc10049-request.104172a3` |
| `hora/testdata/rfc10049-resposta.104172a3` | `testdata/rfc10049-response.104172a3` |
| `hora/testdata/rascunho-pedido.071039e5` | `testdata/rfc-request.071039e5` |
| `hora/testdata/rascunho-resposta.071039e5` | `testdata/rfc-response.071039e5` |

O primeiro par é um pedido e a resposta da versão 1 do Roughtime (RFC
10049), gerados pelo servidor do Roughenough com uma semente de teste. O
segundo é uma captura de maio de 2025 de um servidor da época dos rascunhos
(versão `0x8000000c`). Os casos de `hora::resposta` conferem que o primeiro
passa e o segundo é recusado. É a única conferência externa do formato que
este repositório tem sem rede: o servidor de teste do pacote usa o mesmo
escritor de mensagens que o pedido, e escritor e leitor errando juntos só
aparecem contra bytes de outra implementação.

Obtido do pacote `roughenough-protocol` 2.2.0, no crates.io, de 2026-10-12,
publicado do commit `16012fc1fd3d70ccdffeb8f00794bc124ca9e3d1` de
<https://github.com/int08h/roughenough>, em `crates/roughenough-protocol`. O
pacote é MIT OU Apache-2.0; os arquivos ficam sob a MIT, com o aviso abaixo.
O Duke não depende do Roughenough: nem o código, nem o pacote, entram no
build.

```text
Copyright 2025 the Roughenough Project Contributors

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

## DFINITY — o Internet Computer

O pacote `web3` (módulo `icp`) é um subconjunto `no_std` do cliente do
Internet Computer, escrito aqui e conferido nos testes contra as
bibliotecas oficiais da DFINITY, que só entram como dependências de teste
(ver `web3/Cargo.toml`). Uma função é porte de código delas:

| Arquivo do Duke | Origem |
|---|---|
| `web3/src/icp/assinatura.rs` — `verificar`, a regra ZIP215 da assinatura de um nó | `ic-ed25519` 0.6.0 (`dfinity/ic`, `packages/ic-ed25519`, commit `52d3ede621e1bbc4d51df92ad39eeec850d3d744`) — `PublicKey::verify_signature`, `Signature::from_slice` e `compute_challenge` |

O porte troca o `curve25519-dalek` 4 pelo 5 que o projeto já usa, devolve
um `bool` e não traz a verificação em lote; a conta é a mesma, e os testes
a conferem contra o `ic-ed25519` em todos os pontos de ordem pequena e
codificações não canônicas que separam as regras.

Os testes do pacote usam também os exemplos da *Internet Computer
Interface Specification* (`dfinity/portal`, commit
`ed742236de3b54ed56161f188913536259941a12`): a árvore de hash de exemplo e
a podada, com a raiz e as procuras; o id de pedido de exemplo, campo a
campo; e os Principals `em77e-bvlzu-aq`, `2vxsx-fae` e `aaaaa-aa`.

Ficam no binário dos programas, sem modificação, como dependências
normais: `ic-verify-bls-signature` 0.6.0 (Apache-2.0), para a assinatura
BLS dos certificados, e `ic_bls12_381` 0.10.1 (MIT OU Apache-2.0), por
baixo dela.

O texto da Licença Apache 2.0 está em [`licencas/Apache-2.0`](licencas/Apache-2.0).

```text
Copyright © 2021 DFINITY Foundation   (ic-ed25519)
Copyright 2022 DFINITY Foundation     (dfinity/portal)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
