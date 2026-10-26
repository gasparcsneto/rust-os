# Operar um Duke

Este guia é para quem recebe uma máquina com o Duke e precisa pô-la de pé,
mantê-la e recuperá-la: a máquina de referência, a imagem e o que ela leva,
a rede, os comandos de todo dia, o que fazer quando algo dá errado — e o
que o Duke ainda não faz, com o porquê.

Nada aqui é um caminho à parte. Todo comando deste guia passa pelo mesmo
modelo de todos os outros — **identidade → autoridade → política → gate →
recurso → auditoria → proveniência → persistência** —: quem pede é uma
identidade registrada, age com um papel, a política enumera o que o papel
pode e sobre quê, o gate decide pedido a pedido e grava a decisão, e o que
muda o estado vai ao journal antes de valer. Não há conta de root nem
modo de manutenção: o papel `sistema` é a autoridade máxima, e mesmo ele
tem as permissões enumeradas, sem curinga.

## A máquina de referência

O Duke não tenta rodar em todo hardware. A máquina abaixo é a que a suíte,
a bancada de persistência e a CI exercitam a cada commit — e é a que se usa
para pôr o Duke em produção hoje: uma máquina virtual, num hipervisor com
KVM ou no QEMU, ou uma nuvem que entregue os mesmos dispositivos.

| | x86_64 | aarch64 |
|---|---|---|
| Máquina | `pc` (q35 também serve) | `virt` (GICv2) |
| Firmware | UEFI (OVMF); o iniciador do Duke em `\EFI\BOOT\BOOTX64.EFI` | UEFI (AAVMF), com o device tree publicado (`acpi=off`), ou o kernel direto (`-kernel`) |
| Núcleos | 1 a 64 | 1 a 8 |
| Memória | 128 MiB ou mais; o heap do kernel é 1/16 da utilizável, entre 8 e 256 MiB | igual |
| Disco | **NVMe** (namespace 1, bloco de 512) **ou** virtio-blk; o firmware boota dele | NVMe ou virtio-blk, no PCIe (ECAM) |
| TPM 2.0 | TIS (`tpm-tis`) ou CRB (`tpm-crb`) — um TPM físico ou o `swtpm` | TIS por MMIO (`tpm-tis-device`) |
| Rede | virtio-net; DHCP ou o `/etc/duke/rede` | igual |
| Relógio | o CMOS | a PL031 |
| Console | a serial COM1 (o log, para pessoas), COM2 (o canal do agente), o console virtio (agentes), TCP 7070 | a única PL011 da máquina (o canal do agente; o log sai por `log.tail`), o console virtio, TCP 7070 |
| Vídeo | a VGA da máquina ou virtio-gpu | bochs-display ou virtio-gpu |
| Energia | ACPI: o registrador de reinício da FADT, 0xCF9, o 8042; o S5 pela FADT e pela DSDT | PSCI `SYSTEM_RESET` e `SYSTEM_OFF` |
| Teclado | PS/2, USB (xHCI) | virtio, USB (xHCI) |

Sem TPM a máquina sobe, mas nada de autoridade muda: o journal não tem
âncora contra rollback, e a persistência se declara indisponível — ver
[`PERSISTENCIA.md`](PERSISTENCIA.md). Sem disco, idem. Sem rede, tudo o que
não é rede continua.

O que não é suportado está em [O que fica de fora de
propósito](#o-que-fica-de-fora-de-propósito-grupo-c): placas de rede e
controladores de disco físicos além do NVMe, ACPI no ARM, USB de
armazenamento.

Uma ida de 16 KiB ao disco, medida pelo caso `nvme: a medida de uma ida`
da suíte — a média de 64, no QEMU sem aceleração, num hospedeiro de 4
núcleos:

| | NVMe: leitura | NVMe: escrita | NVMe: descarga | virtio-blk: leitura |
|---|---|---|---|---|
| x86_64 | 161 µs | 1 474 µs | 1 427 µs | 146 µs |
| aarch64 | 125 µs | 1 156 µs | 1 284 µs | 132 µs |

É a conta do emulador, não a do disco: a escrita e a descarga do NVMe do
QEMU vão ao arquivo do hospedeiro, com o cache de escrita que o
controlador anuncia. Numa máquina nova, o mesmo caso diz o número dela no
log.

## A imagem

`cargo xtask build` (e `--arch aarch64`) gera o disco inteiro, 304 MiB,
GPT:

| Partição | Setores (512 B) | O que é | Quem escreve |
|---|---|---|---|
| ESP (FAT32) | 2 048 + 98 304 | o iniciador UEFI e o kernel | ninguém, depois da imagem |
| raiz (Btrfs) | 100 352 + 327 680 | os programas e o `/etc/duke` | ninguém: o VFS é só de leitura |
| estado (tipo do Duke) | 428 032 + 32 768 | o journal da persistência | o journal, pela janela de estado |
| armazém (tipo do Duke) | 460 800 + 131 072 | o volume cifrado do armazém | o volume, pela janela do armazém |

O kernel escreve **só** nas duas últimas, e cada uma só pelo nome dela: a
camada de bloco ([`kernel/src/bloco.rs`](../kernel/src/bloco.rs)) recusa
qualquer escrita fora da janela, em qualquer driver.

O que a raiz leva em `/etc/duke`, e quem o lê:

| Arquivo | O que é |
|---|---|
| `politica` | os papéis, as permissões e o alcance de cada um — [`SEGURANCA.md`](SEGURANCA.md) |
| `agentes` | as chaves públicas dos agentes que podem abrir uma porta, e o papel de cada um |
| `administradores` | as credenciais de quem prova uma operação administrativa, e o quórum |
| `privado/pessoas` | o registro das pessoas: o verificador da senha, nunca a senha |
| `privado/chave` | a chave do Duke — ver [o grupo B](#a-identidade-do-duke-nasce-na-imagem) |
| `editores` | as chaves dos editores de código, para o código de fora da imagem |
| `tempo`, `dominios` | as fontes de hora e os domínios de assinatura |
| `rede` | opcional: a rede sem DHCP — ver [A rede](#a-rede) |

O `privado/` não é alcançável por caminho nenhum de dentro da máquina: nem
um processo, nem um agente com `fs.read`.

### O primeiro boot

A imagem é escrita no disco da máquina — o arquivo vira o disco da VM, ou
um `dd` para o disco. No primeiro boot o kernel cria a âncora no TPM, o
journal na partição de estado e o volume do armazém na dele, e sela no TPM
a semente das chaves de assinatura. Daí em diante cada boot confere o
journal contra a âncora: um disco devolvido a uma fotografia anterior, um
TPM trocado ou limpo, são recusados, e a máquina sobe sem autoridade nova —
ver *R6* em [`PERSISTENCIA.md`](PERSISTENCIA.md).

### Provisionar as identidades

As identidades da máquina nascem na imagem: os agentes, os administradores,
as pessoas. Depois do boot, mudar quem existe e com que papel é uma
**operação administrativa**: o administrador pede um desafio
(`admin.challenge`), assina e executa (`admin.execute`) — e a operação passa
pela política e vai ao journal como qualquer outra:

- `agent.register`, `agent.revoke`, `agent.suspend`, `agent.resume`;
- `person.register`, `person.revoke`, `credential.rotate`,
  `credential.suspend`, `credential.resume`, `session.revoke`;
- `policy.assign` (o papel de uma identidade), `policy.write` (a política);
- `admin.revoke` — a revogação de um administrador, por quórum.

## A rede

Por padrão, DHCP. Para uma máquina sem DHCP, a imagem leva
`/etc/duke/rede`:

```text
# A rede do servidor da sala 3.
endereco 192.168.10.5/24
roteador 192.168.10.1
dns 192.168.10.1
dns 9.9.9.9
```

- `endereco` é obrigatório, uma vez, com o prefixo de 1 a 30;
- `roteador` é opcional, uma vez, e tem de ser outra máquina da sub-rede;
- `dns`, até três.

Com o arquivo, a pilha não pergunta ao DHCP. Um arquivo que não se lê não
cai para o DHCP em silêncio: a máquina fica **sem endereço**, nada disca, e
o `net.info` diz por quê:

```bash
$ cargo xtask agent net.info
{… "address":null,"gateway":null,"dns":[],"mode":"static-invalid",
 "config_error":"o roteador nao e outra maquina da sub-rede do endereco", …}
```

`mode` é `dhcp`, `static` ou `static-invalid`. Os servidores de DNS — os do
DHCP ou os do arquivo — são informação para quem resolve nomes, não
alcance: falar com qualquer destino continua sendo um `net.connect`
decidido pela política, destino por destino.

## Os comandos de todo dia

Todos pelo canal do agente — `cargo xtask agent <comando> [parâmetros]` na
bancada, ou um agente pela porta dele — ou pelo console, por uma pessoa.
`agent.describe` lista todos, com os parâmetros. Os de operação:

| Para | Comando | Permissão | Quem tem, na política da imagem |
|---|---|---|---|
| ver a máquina | `system.info`, `threads.stats`, `heap.stats`, `irq.stats` | `system.read` | observador, operador, sistema, administrador |
| ver os processos | `process.list` | `system.read` | os mesmos |
| conter um processo | `process.isolate`, `process.release` | `process.isolate` | sistema; segurança, só processos de observador e de operador; administrador pela prova |
| encerrar um processo | `process.terminate` | `process.terminate` | sistema; administrador pela prova |
| reiniciar, desligar | `system.reboot`, `system.poweroff` | `system.power` | sistema; administrador pela prova |
| ver o disco | `disk.info` | `system.read` | observador, operador, sistema, administrador |
| conferir o armazém | `fs.verify` | `fs.read`, no caminho | quem lê o caminho |
| ver a rede | `net.info` | `system.read` | observador, operador, sistema, administrador |
| ver a auditoria | `audit.tail`, `audit.verify` | `audit.read` | sistema, segurança, administrador |
| ver o log | `log.tail` | `log.read` | observador, operador, sistema, administrador |

Os papéis de serviço — `tempo`, o do serviço de hora, e `seguranca`, o do
tecido de segurança — não leem o estado da máquina: só o que o serviço
deles precisa.

O papel que encerra alcança observador, operador e sistema — **nunca** um
processo de administrador —, e a segurança só contém: encerrar é do
sistema. `process.terminate` isola o processo na hora (o pedido em curso
dele é recusado no commit, as conexões caem) e o processo morre no próximo
ponto seguro — a entrada ou a volta de uma chamada de sistema, ou a
interrupção que o pega no anel do usuário. O pai colhe um morto.

`system.reboot` e `system.poweroff` gravam o pedido na auditoria e no
journal **antes** de responder — sem ele no disco, a máquina segue ligada.
Meio segundo depois, as gravações param (a operação em curso termina,
nenhuma começa), o disco é descarregado, o NVMe recebe o aviso de
desligamento, e o firmware reinicia ou corta a energia. O `system.info`
diz como (`reboot_via`, `poweroff_via`); uma máquina cujo firmware não diz
como desligar — nem o S5 da ACPI, nem a PSCI — recusa o pedido e segue
ligada, em vez de parar as gravações e ficar parada.

## Quando algo dá errado

| Sintoma | O que dizer à máquina | O que acontece |
|---|---|---|
| Um processo em laço, ou que não responde | `process.list`, depois `process.terminate` | isolado na hora, morto no próximo tique |
| Um agente ou uma credencial que se comporta mal | `agent.suspend`, `credential.suspend` (o sistema, ou o administrador pela prova) | cada pedido seguinte é `DENY_CONTAINED` |
| Um bloco do armazém que não abre | `fs.verify {"path":"/armazem"}` | os caminhos que não abrem, um por um; a verificação só lê |
| A verificação diz blocos vivos livres no mapa (`live_blocks_free_in_map`) | nada mais de escrita; `system.reboot` | é uma conta errada do kernel, só na memória: o boot refaz o mapa a partir dos metadados do journal, e a verificação volta a conferir |
| A rede sem endereço | `net.info` | `mode` e `config_error` dizem se é o DHCP ou o arquivo |
| A persistência indisponível | `system.info` | `persistence.state` e `persistence.reason`: o disco, o TPM, o journal recusado — ver [`PERSISTENCIA.md`](PERSISTENCIA.md) |
| Por que um pedido foi recusado | `audit.tail` | quem pediu, por que processo, o papel, o recurso, o código da decisão e o motivo |
| A máquina não responde | corte a energia | o journal e o volume do armazém são feitos para isso: o que estava confirmado volta igual, e a cadeia da auditoria continua |

Cortar a energia é seguro — é o que a bancada de persistência faz centenas
de vezes por execução, em cada fronteira de cada operação. Reiniciar pelo
comando é melhor só porque espera a operação em curso acabar.

Um arquivo do armazém com um bloco que não abre está perdido: a cifra
autenticada recusa o que o disco devolveu, e nada o devolve — apague-o
(`fs.delete`) e grave de novo de onde ele veio. Não há cópia de segurança
— ver [o grupo B](#cópia-de-segurança-e-restauração). A verificação não
para as gravações: um arquivo gravado de novo enquanto ela anda conta em
`changed`, e não como bom nem como ruim — confira-o de novo.

## O que o Duke ainda não faz (grupo B)

Cada item abaixo pediria uma decisão nova sobre identidade, autoridade,
confiança ou custódia — e por isso não foi implementado. Para cada um: o
problema, por que importa, o impacto, as alternativas, a recomendação e os
invariantes que ele toca.

### Atualizar o kernel e a imagem

- **Problema.** Não há como trocar o kernel, os programas da imagem ou a
  política da imagem numa máquina em uso, a não ser regravando o disco.
- **Por que importa.** Uma correção de segurança precisa chegar à máquina
  sem apagar o journal, o armazém e a âncora.
- **Impacto.** Hoje, atualizar é reinstalar: o estado da máquina vai junto.
- **Alternativas.** (a) Duas ESPs e duas raízes (A/B), o iniciador boota
  a marcada e volta à outra se o boot novo não confirmar; (b) uma imagem
  assinada por uma chave de atualização, conferida pelo iniciador; (c) um
  contador de versão no TPM, contra a volta a uma imagem antiga e
  vulnerável.
- **Recomendação.** (a) + (b) + (c): A/B no iniciador, a assinatura por
  uma chave de atualização fixada na imagem anterior, e o anti-rollback
  num índice do TPM, como o da âncora do journal.
- **Invariantes.** Uma **raiz de confiança nova** (a chave de atualização)
  e uma semântica nova de confiança no boot (quem pode trocar o código que
  decide). É exatamente o que o pedido manda não decidir sozinho.

### A identidade do Duke nasce na imagem

- **Problema.** A chave do Duke (`/etc/duke/privado/chave`) vem na imagem:
  quem tem a imagem tem a chave, e duas máquinas da mesma imagem são o
  mesmo Duke.
- **Por que importa.** Numa frota, cada máquina precisa ser uma identidade.
- **Alternativas.** (a) A chave gerada no primeiro boot e selada no TPM,
  como a semente das chaves de assinatura (ICP-5); (b) gerada fora e
  injetada por máquina na instalação; (c) derivada de um segredo do TPM.
- **Recomendação.** (a), com o registro público da chave nova levado aos
  agentes por um administrador.
- **Invariantes.** A identidade do Duke e a custódia da chave dele; a
  confiança dos agentes no aperto de mão (eles fixam a pública).

### O botão de energia

- **Problema.** O botão de energia da máquina (o evento ACPI) não faz
  nada: desligar é um comando.
- **Alternativas.** (a) O botão como uma identidade de hardware com um
  papel na política (só `system.power`); (b) o botão só registra e pede a
  um administrador; (c) nada — como hoje.
- **Recomendação.** (b): o evento vai à auditoria, e o desligamento
  continua sendo de quem tem `system.power`.
- **Invariantes.** Um evento de hardware virando autoridade — uma
  identidade que não é pessoa, agente nem processo.

### A pessoa troca a própria senha

- **Problema.** Só um administrador troca a credencial de uma pessoa
  (`credential.rotate`, pela prova).
- **Alternativas.** (a) A pessoa troca, provando a senha atual; (b) a troca
  pedida pela pessoa e confirmada por um administrador.
- **Recomendação.** (a), com o verificador novo no journal como o de
  `credential.rotate`.
- **Invariantes.** Quem custodia a credencial: hoje a mudança de uma
  credencial é sempre administrativa.

### Cópia de segurança e restauração

- **Problema.** Não há cópia do armazém nem do estado.
- **Por que importa.** Um disco perdido leva tudo; um bloco que não abre
  é um arquivo perdido.
- **Alternativas.** (a) Exportar o armazém cifrado para outra máquina,
  arquivo a arquivo, pelo gate; (b) uma fotografia inteira da partição,
  que a âncora recusaria ao voltar — por desenho.
- **Recomendação.** (a) para os dados, sem restaurar estado de autoridade:
  devolver o journal a uma fotografia anterior é justamente o rollback que
  a âncora existe para recusar.
- **Invariantes.** A âncora contra rollback e o que é "o estado atual" de
  uma máquina.

## O que fica de fora de propósito (grupo C)

- **Watchdog e reinício automático depois de um pânico.** O pânico deixa a
  máquina parada e inspecionável — o post-mortem é uma decisão fechada.
- **ACPI no ARM, AHCI/SATA, placas de rede físicas, USB de armazenamento.**
  A máquina de referência é a virtual, com NVMe; cada driver a mais é
  superfície sem cliente.
- **IPv6.** A rede de referência é IPv4, com DHCP ou o arquivo.
- **A ABI do Linux.** O Duke tem a interface nativa dele — decisão fechada.
- **Do IC:** delegação, chaves de sessão, outra identidade ou Principal,
  mTLS, HTTP/3, QUIC, EVM, SDK — o IC é um protocolo de programa, e nada
  disso tem uma necessidade demonstrada.
