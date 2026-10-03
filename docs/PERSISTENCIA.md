# Persistência — desenho do ponto 7

> **Estado: em implementação, aprovada.** O ponto 7 entra em fases — ver
> [Fases e estado](#fases-e-estado) no fim. Os requisitos abaixo foram
> escritos antes da primeira linha, e cada fase diz quais deles já valem.

Hoje o disco é só leitura. Tudo o que muda em tempo de execução — mensagens,
`agent.register`, `policy.write`, `admin.revoke`, a revogação de pessoas e
sessões, a auditoria — vale até o próximo boot. Para mensagens isso é uma
limitação. Para a revogação de uma credencial administrativa é um **buraco
de segurança**: a credencial revogada volta com a imagem, e volta válida.

## O que o ponto 7 constrói

1. **Uma área de dados gravável**, separada da imagem: o Btrfs continua só
   leitura (a Fase 8 do README explica por quê), e o estado vai para uma
   partição própria.
2. **Um journal só de acréscimo.** Cada mudança de estado vira um registro:
   tamanho, tipo, geração, conteúdo, o hash do registro anterior e um MAC.
   Nada é reescrito no lugar.
3. **Escrita atômica e recuperação depois de queda de energia.** Um registro
   só conta depois de inteiro no disco, com o `flush` do dispositivo
   confirmado. No boot, uma cauda incompleta — o registro que a queda cortou
   no meio — é descartada. Qualquer outro defeito não é descartado: é
   recusado (ver R4).
4. **O boot repassa o journal** sobre o estado que vem da imagem, e só então
   abre as portas do agente.
5. **Confidencialidade em repouso**: o conteúdo dos registros de mensagem é
   cifrado com uma chave derivada da chave do Duke, por HKDF com rótulo
   próprio. O corpo de uma mensagem não pode ficar legível no disco.
6. **Por cima disso**, a tabela de mensagens: cada transição é um registro,
   a época aleatória do id vira uma época persistente, a janela de nonces e
   os prazos sobrevivem ao boot.

O mesmo journal serve a todo estado administrativo, e não só às mensagens.

## Requisito de segurança: a revogação administrativa sobrevive ao reboot

**Uma credencial administrativa revogada não pode reaparecer como válida
depois de uma reinicialização.** A persistência preserva também a geração
que impede o replay e a restauração de um estado administrativo anterior.

O requisito se desdobra no seguinte.

### R1. A revogação é uma lápide permanente

`admin.revoke` grava no journal uma **lápide**: a chave X25519 da
credencial e a sua chave pública Ed25519, a geração, o hash do desafio e a
versão da política sob a qual o quórum assinou.

- A lápide nunca é apagada nem compactada. Uma compactação futura do journal
  carrega todas as lápides para o journal novo.
- Não existe operação de "desrevogar". A regra de hoje fica: nenhuma
  operação de recuperação contorna o quórum.
- **A lápide vence a imagem.** O registro efetivo de administradores é o da
  imagem *menos* as lápides. Uma imagem nova que traga de novo uma chave
  revogada não a reabilita, porque a chave continua sob a lápide. A
  credencial que substitui uma revogada é uma chave nova.
- A lápide cobre a credencial nos dois papéis: ela não prova
  (desafio-resposta X25519), não assina quórum (Ed25519) e não recebe
  mensagens.

### R2. Gravar antes de responder

A ordem da revogação passa a ser: conferir o quórum → gravar a lápide no
journal com `flush` confirmado → marcar em memória → responder → auditar.

Um `admin.revoke` respondido com sucesso é, portanto, uma revogação que já
sobrevive à queda de energia. Se a gravação falhar, a credencial é marcada
revogada em memória mesmo assim, porque nunca se fica mais fraco que hoje.
A resposta diz explicitamente que a revogação **não é durável**, a
auditoria registra isso, e o kernel recusa novas operações administrativas
até conseguir gravar a lápide. Assim, quem quebra o disco não mantém uma
credencial revogada viva de propósito.

### R3. No boot, nada administrativo antes do journal

O boot carrega o registro da imagem, repassa o journal, aplica as lápides
e só então:

- conta as credenciais ativas, para a regra de "restam ao menos M";
- emite o primeiro desafio administrativo;
- abre as portas do agente e a serial administrativa.

Não há janela, por curta que seja, em que a credencial revogada da imagem
esteja ativa. Se as lápides deixarem menos de M credenciais ativas, o
quórum fica impossível, e isso é relatado no boot. Não há recuperação
automática.

### R4. Falhar fechado

Um journal que existe mas não confere — MAC errado, elo quebrado, geração
fora de sequência, um registro inteiro que não se lê — **não** faz o
kernel cair de volta no registro da imagem. Cair de volta seria
exatamente a ressurreição que o R1 proíbe.

O sistema sobe com a administração bloqueada: nenhuma operação
administrativa é aceita, a recusa diz o motivo, e o boot relata o registro
em que a conferência parou. Só a cauda incompleta do item 3 é descartada
em silêncio, e mesmo ela fica no relatório de boot.

A ausência do journal é distinguida da destruição dele. A área de dados
nasce com um registro de abertura, e uma área de dados vazia num sistema
que já tem geração registrada (ver R6) é uma restauração, e não um sistema
novo.

### R5. Uma geração administrativa monotônica

Um contador de 64 bits, a **geração**, cresce em todo registro
administrativo: lápide, `agent.register`, `policy.write`, revogação de
pessoa. Ele é persistido em cada registro, que traz também o hash do
anterior, como a cadeia da auditoria. A geração e a cadeia dão três
coisas:

- **Não há replay de registro.** Um registro só é aceito com
  `geração = anterior + 1` e o elo certo. Um registro copiado de outro ponto
  do journal, ou de outro journal, quebra a sequência.
- **A versão da política não recomeça.** Hoje ela volta a 1 a cada boot
  (`autorizacao::VERSAO_DA_POLITICA`), e o mesmo número passa a descrever
  políticas diferentes em boots diferentes. Com o journal, a versão continua
  de onde parou, e o conteúdo canônico do quórum nunca vê o mesmo número
  para dois estados.
- **A assinatura amarra o estado.** O conteúdo canônico do quórum
  (`sigilo::quorum::Conteudo`) ganha a geração, numa versão 2 do formato.
  Uma assinatura passa a dizer sob qual estado administrativo foi dada, e
  não vale sob outro.

Os desafios continuam sendo só da memória, e um boot os descarta todos. Uma
assinatura capturada antes do reboot não vale depois, porque o nonce do
desafio é novo. A geração no conteúdo fecha o caso restante: um estado
restaurado em que alguém tentasse reapresentar o mesmo conteúdo.

### R6. Restauração de um estado anterior

A geração protege contra replay **dentro** do journal. Ela sozinha não
protege contra quem troca o journal inteiro por uma cópia antiga, feita
antes da revogação. Essa cópia é consistente em si mesma: MAC certo, elos
certos, geração menor.

O kernel, olhando só para o disco, não tem como distinguir a cópia antiga
da verdadeira. Para detectar a restauração é preciso uma **âncora** fora
do alcance de quem escreve no disco. O desenho prevê duas camadas:

1. **Âncora no signatário (sempre presente).** A ferramenta de assinatura
   do administrador guarda a maior geração que já assinou e recusa assinar
   um conteúdo com geração menor. Ela também mostra a geração e o elo do
   journal antes de assinar. Quem tem a chave privada é também quem guarda a
   memória do estado: uma restauração aparece na primeira operação de
   quórum depois dela, e nenhuma operação administrativa passa sobre o
   estado restaurado. `system.info` passa a publicar a geração e a cabeça do
   journal, para que qualquer agente compare.
2. **Âncora de hardware (decidida).** Um contador monotônico no NV de um
   TPM 2.0, fora do disco. Cada gravação do journal — e não só as
   administrativas: a âncora protege o estado persistente **inteiro** —
   avança o contador, e o journal guarda o valor a que corresponde. No
   boot, antes de liberar qualquer operação administrativa, o kernel lê o
   contador e recusa um journal anterior a ele. No QEMU, o TPM é o
   `swtpm`; o driver fala TIS, a interface dos TPMs discretos, atrás de
   uma camada de transporte, e a âncora é uma interface acima dos comandos
   do TPM — um TPM físico entra sem mudar a lógica da persistência nem a
   da autorização.

As duas camadas são mecanismos distintos, e não se substituem. A geração
do R5 amarra cada assinatura ao estado administrativo sob o qual foi dada
— protege a validade e a ordem das assinaturas. O contador da âncora
amarra o disco inteiro ao TPM — protege contra a restauração de um disco
antigo. A geração não sobe a cada mensagem; o contador sobe a cada
gravação.

O que fica de fora, e convém dizer exatamente: quem tem o TPM **e** o disco
— limpa o TPM, ou o troca — faz a âncora sumir. O kernel não aceita isso
como sistema novo: um journal que diz ter sido ancorado, num TPM sem o
contador, é recusado como restauração (R4), e a administração sobe
bloqueada.

### R7. Testes que o ponto 7 terá de ter

Os testes serão escritos antes da implementação, como nas etapas
anteriores:

- **Reboot de verdade na fumaça.** Revogar por quórum, desligar, subir de
  novo sobre o mesmo disco, e conferir que a credencial não prova, não
  assina quórum, não conta para o M e não recebe mensagens. A auditoria
  mostra a lápide.
- **Imagem que traz de volta a chave revogada:** ela continua revogada.
- **Queda no meio da gravação** (o QEMU morto durante o `flush`): ou a
  revogação foi respondida e sobrevive, ou não foi respondida. Nunca
  respondida e perdida.
- **Journal adulterado** (MAC, elo, geração repetida ou pulada): a
  administração sobe bloqueada, e nenhuma credencial da imagem volta.
- **Journal antigo restaurado:** com a âncora de hardware, o boot recusa;
  sem ela, o signatário recusa a primeira assinatura.
- **Versão da política e geração contínuas** entre boots.
- **Mutações dirigidas:**
  - repassar o journal depois de abrir as portas;
  - aplicar a imagem por cima das lápides;
  - aceitar MAC errado;
  - aceitar um salto de geração;
  - zerar a versão da política no boot;
  - responder antes do `flush`;
  - cair no registro da imagem quando o journal falha;
  - o signatário aceitar uma geração menor.

  Cada uma tem de ser morta por um caso nomeado.

## Como ficou (7.0 a 7.3)

### As peças

- `kernel/src/virtio/blk.rs`: escrita e descarga (`VIRTIO_BLK_F_FLUSH`),
  numa janela fixada uma vez no boot sobre a partição de estado. Sem
  descarga, nenhuma escrita é aceita.
- `ancora/` e `kernel/src/tpm.rs`: os comandos TPM 2.0 do contador de NV, e
  o transporte TIS até o chip. O índice é `0x0180D0E0`, com senha derivada
  da chave do Duke, sem política, sem bloqueio contra força bruta.
- `diario/`: o formato do journal, a leitura que confere cada registro, o
  escritor, o julgamento contra a âncora e o relógio que não volta.
- `kernel/src/persistencia.rs`: o boot, a gravação, o portão das operações
  administrativas e a diferença que vira registro. É o único módulo que
  escreve no disco — o `cargo xtask invariantes` recusa outro.

### O boot

1. O registro da imagem, a política e as pessoas carregam.
2. O journal é lido e cada registro autêntico é reaplicado — **antes** de
   qualquer conferência de âncora, e mesmo que ela recuse: o que o journal
   diz é mais recente que a imagem, e só pode tirar o que ela dá.
3. Disco durável? TPM presente? Sem um deles, a persistência fica
   *indisponível*.
4. A âncora é aberta e julgada contra o último registro: *confere*;
   *completar* (o último registro foi gravado e o contador não andou — ele
   anda agora); *novo* (sem journal e sem âncora — ela é criada); ou
   *recusado* (disco anterior à âncora, âncora anterior ao disco, âncora
   ausente com journal, journal ausente com âncora).
5. Disponível, um registro de boot é gravado.
6. Só então as portas abrem.

### O portão

Toda operação administrativa — de uma credencial ou de quórum — exige a
persistência *disponível*. Indisponível ou recusada, **nenhuma credencial
administrativa é aceita**, nem para ler a própria caixa: sem o journal
confirmado pela âncora, o kernel não sabe quais credenciais foram
revogadas. É mais estrito do que o desenho inicial (que bloqueava só o que
muda autoridade), e foi a bancada que mostrou a razão: com o registro da
lápide estragado, a credencial revogada continuava lendo e mandando
mensagens como administradora.

Disponível, a operação acontece, e o que ela mudou — a diferença entre o
estado antes e depois, com o nome da operação — vira **um** registro,
escrito, descarregado e ancorado antes da resposta. Se a gravação falha, o
que a operação concedeu é desfeito, o que ela tirou fica, e a persistência
passa a indisponível.

### A geração

Cada registro de operação sobe a geração em um, e só ele: quem a calcula é
o escritor do journal, pelo tipo do registro, e não quem pede a gravação. O
leitor confere a mesma regra em cada registro depois do primeiro — um
registro autêntico com a geração saltada ou voltada para a leitura ali,
como um elo quebrado. Ela está em cada registro,
no `system.info`, em cada desafio de quórum, e no conteúdo que as
credenciais assinam (`sigilo::quorum`, formato 2): uma mudança de
autoridade entre o desafio e o pedido derruba as assinaturas. O signatário
do `xtask` guarda a maior geração que já assinou, e recusa uma menor.

### O relógio

O tempo lógico é o RTC com um piso: o tempo do último registro gravado.
Ele nunca fica abaixo desse piso — nem num boot com o RTC atrasado. Uma
leitura do relógio que não grava nada não sobe o piso; o que depende do
tempo e precisa sobreviver (os prazos das mensagens, na 7.4) grava o tempo
junto.

### Os testes

- **No hospedeiro:**
  - o journal cortado em cada setor de uma gravação;
  - cada bit de um journal trocado;
  - registros de outro journal e fora de ordem;
  - registros autênticos — escritos com a chave — com a sequência, a
    âncora, um reservado ou a geração fora da regra;
  - a chave errada;
  - a partição cheia;
  - o julgamento inteiro;
  - a âncora contra um TPM simulado e contra o `swtpm`;
  - o texto da política, que volta igual.
- **Na suíte do kernel:**
  - a escrita fora da janela;
  - a janela que não se redesenha;
  - o contador do TPM pelo TIS;
  - o RTC;
  - a persistência aberta e ancorada;
  - uma operação, um registro;
  - o portão sem persistência, pela serial e pelo quórum;
  - a gravação que falha;
  - a lápide que vence a imagem;
  - as entradas reaplicadas e as erradas recusadas;
  - a geração no quórum.
- **Na bancada (`cargo xtask persistencia`):**
  - a revogação que sobrevive ao corte;
  - registro, papel, política, versão e geração que sobrevivem;
  - a fotografia antiga recusada;
  - o journal adulterado recusado sem que a credencial revogada volte;
  - o journal recusado que ainda tira: o agente revogado antes do registro
    estragado continua fora;
  - sete quedas no meio da gravação;
  - o TPM limpo;
  - a máquina sem TPM;
  - o relógio que volta;
  - o signatário.

## Decisões tomadas

- **Âncora:** o TPM 2.0, com um contador monotônico de NV; o `swtpm` como
  TPM de desenvolvimento no QEMU, nas duas arquiteturas.
- **Relógio:** o RTC de hardware (CMOS no x86, PL031 no ARM), com um piso
  gravado no journal: o tempo lógico nunca volta atrás do último valor
  gravado. O tempo desde o boot não serve de relógio de validade.
- **Dados:** uma partição dedicada no mesmo disco, com um tipo GUID do
  Duke (`6d7a3c1e-5b2f-4e8a-9c41-d0a7e5c3f911`), de 16 MiB. A escrita do
  kernel fica restrita a ela, e só o módulo do journal escreve. A ESP e a
  raiz continuam intocáveis.
- **Persistência indisponível:** as mensagens podem continuar só em
  memória, dizendo isso; as operações que mudam o estado de autoridade
  ficam bloqueadas. Não há exceção para o `sistema`.
- **Ordem:** 7.0 → 7.1 → 7.2 → 7.3, um relatório, e então 7.4 → 7.5 →
  7.6 → 7.7.

## Fases e estado

| Fase | O quê | Estado |
|---|---|---|
| 7.0 | A bancada: partição de estado, TPM em toda máquina, relógio, vários boots com corte de energia, fotografia e restauração da partição | feita |
| 7.1 | Escrever no disco (só a partição de estado, com `FLUSH`), o TPM pelo TIS, o RTC | feita |
| 7.2 | O journal: registros autenticados, geração, âncora, piso do relógio | feita |
| 7.3 | O estado administrativo durável (R1–R6) | feita |
| 7.4 | Mensagens persistentes | — |
| 7.5 | Auditoria persistente | — |
| 7.6 | Compactação e disco cheio | — |
| 7.7 | O que restar da âncora (TPM físico, sessão autenticada no barramento) | — |
