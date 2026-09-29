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
