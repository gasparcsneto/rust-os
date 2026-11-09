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
Desde o relógio civil (ver [O tempo](../README.md#o-tempo)), o relógio de
fora é o civil — o RTC até o primeiro acordo das fontes de hora, e a hora
autenticada depois —; o piso é o mesmo.
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

### As mutações

Cada conferência foi tirada ou invertida, uma de cada vez, e a suíte, a
bancada ou um teste do hospedeiro tem de reprovar. As que sobreviveram
ganharam um caso, e o caso foi conferido contra a mesma mutação.

| Mutação | Quem a mata |
|---|---|
| repassar o journal depois de abrir as portas | `cargo xtask invariantes` (a ordem do boot) |
| aplicar a imagem por cima das lápides | suíte: *a lápide vence a imagem* |
| a lápide do journal ignorada | suíte: *a lápide vence a imagem* |
| aceitar MAC errado, elo ignorado, AAD sem elo | hospedeiro: *lê de volta*, *fotografia antiga*, *cada bit trocado* |
| aceitar um salto de geração; a geração que não sobe ou recomeça | hospedeiro: *registro autêntico com cabeçalho errado*, *a geração conta as operações* |
| sequência, encadeamento da âncora ou reservados sem conferência | hospedeiro: *registro autêntico com cabeçalho errado* |
| a escrita fora da janela; a janela fixada duas vezes | suíte: *disco* |
| o portão só para quem muda; o portão aberto; o do quórum tirado | suíte: *sem ela nada de autoridade muda* |
| a geração do desafio não conferida | suíte: *a geração amarra o quórum* |
| a concessão não desfeita; a falha que não deixa indisponível | suíte: *a gravação que falha* |
| responder sem descarga | suíte: *cada operação, um registro*; bancada |
| o contador antes do disco | suíte: *a gravação que falha* |
| o contador que volta com outro valor, aceito | hospedeiro: *só a âncora do registro confirma* |
| o nonce fixo | suíte: *cada operação, um registro* |
| o julgamento ignorado | bancada: *fotografia antiga*, *journal adulterado* |
| o piso do relógio esquecido no boot | bancada: *o relógio lógico* |
| a política do journal ignorada | bancada: *o estado sobrevive* |
| atributos da âncora sem conferência; o avanço sem reler | hospedeiro: `ancora` |
| o texto da política sem quórum, processos ou inclusões | hospedeiro: *o texto volta igual* |
| o relógio sem piso | hospedeiro: *o relógio nunca volta* |
| o signatário aceitar uma geração menor, ou não guardar a que viu | bancada: *o signatário* |

As do 7.4:

| Mutação | Quem a mata |
|---|---|
| o envio, a entrega ou a transição por id sem ir para o journal | suíte: *cada transição é um registro*, *o journal repõe a mesma tabela* |
| sem persistência, a resposta dizer que gravou; `durable` sempre verdadeiro | suíte: *sem persistência, só em memória* |
| a ordem das gravações sem exclusão | suíte: *a ordem das gravações* |
| o journal recusado sem fechar as credenciais, ou deixando a chave de um agente | suíte: *o journal recusado fecha as credenciais* |
| a revogação sem as anulações no registro dela; a anulação sem anotar | suíte: *a revogação e as anulações no mesmo registro* |
| o coletor ou a consulta vencendo sem gravar | suíte: os casos do vencimento, com o journal conferido |
| a reposição ignorando as mensagens | suíte: *o journal repõe a mesma tabela* |
| a época da instalação ignorada | bancada: *as mensagens sobrevivem* |
| o journal recusado repondo as mensagens dele | bancada: *o journal recusado* |
| o prazo no tempo desde o boot | bancada: *o prazo é do tempo lógico* |
| a criação interrompida recusada | bancada: *a queda na criação* |
| qualquer nascimento aceito diante de um journal vazio | bancada: *a fotografia tirada na fronteira, ou na criação* |
| a reposição aceitando versão pulada, id fora de ordem, entrega dupla, volta a pendente, corpo que não é texto | hospedeiro: *repor fora de ordem é recusado* |
| os bytes de um titular ou de um estado trocados ou de tamanho errado | hospedeiro: *titulares e estados vão e voltam* |
| o nascimento sem conferir o índice, não inicializado lido como zero, ou guardado errado | hospedeiro: os casos do nascimento, e o `swtpm` |

As que só a bancada mata só se veem entre dois boots, e é para isso que ela
existe; ela roda na CI nas duas arquiteturas.

## Como ficou (7.4)

### As mensagens no journal

Cada mudança de uma mensagem vai para o journal **antes** da resposta:

- a mensagem aceita, inteira, com o corpo cifrado no registro;
- a entrega da primeira leitura;
- a confirmação, o cancelamento, o vencimento, a anulação, a purga.

A operação muda a tabela e grava o registro do que mudou com a **ordem
das gravações** na mão, e só então responde. A resposta diz
`"durable": true` quando o registro está escrito, descarregado e
ancorado: uma operação respondida assim não volta atrás num reboot. Sem a
persistência — sem TPM, journal recusado, uma gravação que falhou —, a
mensagem continua, só em memória, e a resposta diz `"durable": false` e,
em `memory_only`, por quê.

Um registro de mensagens (`MENSAGENS`) não sobe a geração: mensagem não é
autoridade. A revogação de um titular anula as mensagens dele, e as
anulações vão no registro da própria revogação — uma operação, um
registro.

O que o journal guarda são resultados: a mensagem criada e cada
transição, com a versão. O boot os repõe na ordem, e a tabela reposta é a
mesma — conferido no hospedeiro e na suíte. Ela só vale com o journal
confirmado pela âncora: com ele recusado, ou sem âncora, a tabela começa
vazia e só em memória, porque um disco antigo traria de volta como
pendente o que já foi confirmado ou anulado.

### O tempo e os ids

- **Os prazos são do tempo lógico** — o relógio civil com o piso do
  journal —, com a resolução dele, um segundo. Um prazo não volta a
  correr num boot com o RTC atrasado. O tempo desde o boot só diz ao
  coletor de quanto em quanto olhar.
- **Um vencimento dito é gravado**: o coletor e a consulta que vencem uma
  mensagem gravam o vencimento antes de dizê-lo. Uma vencida não volta a
  pendente.
- **A época dos ids é a da instalação** — os oito primeiros bytes do
  identificador sorteado na abertura do journal. Um id continua o mesmo
  depois de um boot, e o próximo continua de onde parou.
- **As janelas de nonces não vão para o journal.** São de um canal — uma
  sessão, ou os desafios de um administrador —, e nenhum canal atravessa
  um boot: um quadro de uma sessão não se repete em outra, que tem outras
  chaves, e uma operação administrativa precisa de um desafio deste boot.
  O desenho previa que a janela sobrevivesse ao boot; o que ela protege —
  nenhum pedido vale duas vezes — já não depende disso.

### As fronteiras entre o disco e o TPM

- **A ordem das gravações.** O coletor de vencimentos é um fio
  preemptivo. Quem muda o estado que vai ao journal e grava o registro faz
  as duas coisas com a ordem na mão — reentrante pelo mesmo fio, e quem
  espera cede a CPU —, e o journal tem os registros na ordem em que as
  mudanças aconteceram na memória.
- **O nascimento da âncora.** Ao lado do contador, um índice comum do TPM
  guarda o valor com que o contador nasceu. Um journal vazio diante de um
  contador que nunca passou do nascimento é uma criação interrompida — e
  é retomada; diante de um contador que passou, é um disco apagado — e é
  recusado. Antes do 7.4, uma queda entre criar a âncora e gravar a
  abertura deixava o sistema recusado para sempre.
- **O journal recusado fecha as credenciais.** Um journal recusado perdeu
  registros, e o que se perdeu pode ser a revogação de um agente da imagem
  ou de uma pessoa: com ele recusado, o ponto único de decisão não aceita
  chave de agente nem pessoa. A serial e o `sistema`, que não têm
  credencial a revogar, continuam. A persistência só indisponível — sem
  TPM, sem disco durável — não é isso, e as credenciais continuam.

### As quedas, em cada ponto

A bancada tem uma compilação do kernel com pontos de queda: um plano no
último setor da partição diz em que ponto e em que gravação a energia cai,
o kernel avisa pela serial e congela, e a bancada corta a energia. Os
pontos:

- antes de escrever;
- depois de escrever — a escrita chegou ao disco, ou se perdeu por não ter
  sido descarregada;
- depois de descarregar e antes do contador;
- depois do contador e antes da resposta;
- e, na criação da âncora, com o contador definido e nunca avançado,
  avançado sem nascimento, com o nascimento e sem a abertura.

Em todos, o boot seguinte sobe com a persistência disponível, a operação
vale exatamente quando o registro dela está no disco, e a próxima operação
grava. A fotografia tirada na fronteira — o registro no disco e o
contador ainda não avançado —, devolvida depois que o TPM andou, é
recusada; a da criação interrompida também.

## Como ficou (7.5)

### A auditoria no journal

A cadeia da auditoria — a mesma de antes, com os mesmos elos — vai ao
journal. Cada registro do journal, de qualquer tipo, leva no fim os
registros da cadeia que ainda não estão no disco, na ordem da cadeia. O
boot refaz a cadeia a partir deles — a mesma sequência e o mesmo elo —, e
ela continua de onde parou: o que o boot registrou antes de ler o journal
(a política carregada, o desfecho da abertura) é encadeado depois do que
veio do disco.

- **A decisão vai no registro da operação.** Uma operação de autoridade
  registra a decisão que a autorizou — o administrador, o recurso, a
  permissão, o desafio; no quórum, quem assinou e o motivo — **antes** de
  ir ao journal, e a gravação exige que ela vá no mesmo registro. A
  mudança e a decisão entram juntas, ou nenhuma entra: depois de qualquer
  queda, uma mudança de autoridade que está no journal tem a decisão dela
  na cadeia. O que estava pendente antes da decisão e não cabe junto vai
  antes, em registros só de auditoria; a decisão, nunca — se ela não cabe
  com o conteúdo da operação, a gravação falha, e a operação também. Uma operação de mensagem de um agente tem a decisão do ponto
  único antes do efeito, e ela vai no registro da mensagem; uma do
  administrador registra a decisão antes de executar, pelo mesmo motivo.
- **O que não muda estado vai depois.** Uma leitura, uma recusa: vão no
  próximo registro de qualquer tipo, ou num registro só de auditoria
  (`AUDITORIA`) que o coletor grava a cada dois segundos com algo
  pendente — antes, se meio anel está esperando. É a janela do que uma
  queda de energia leva: as decisões sem efeito dos últimos segundos.
- **O que já está no disco se sabe.** `audit.tail` diz `durable` em cada
  registro e `durable_seq` no todo; `system.info` diz quantos registros
  são só de auditoria e até onde ela está gravada. Um registro dito
  `durable` volta igual depois de um corte de energia.
- **Sem persistência, só em memória.** Sem TPM, com o journal recusado,
  depois de uma gravação que falhou: a cadeia continua em memória, e nada
  dela se diz gravado. O journal recusado não tem a auditoria adotada,
  pela mesma razão das mensagens — um disco antigo traria uma cadeia
  antiga —, e o desfecho da abertura (`persistence.open`, com o motivo)
  é o primeiro registro da cadeia nova.
- **A lacuna.** O que sai do anel da memória antes de chegar ao disco —
  mais de um anel inteiro entre duas gravações — não some em silêncio: o
  próximo registro leva uma lacuna, com a primeira e a última sequência
  perdidas e o elo da última. A cadeia refeita continua verificável depois
  dela. Uma operação cuja decisão caiu numa lacuna não vai ao journal.
- **O tempo é o lógico.** O tempo de um registro da auditoria passou a ser
  o RTC com o piso do journal, e não o tempo desde o boot, e a cadeia não
  deixa ele voltar: um registro feito antes de o piso ser lido sobe até o
  anterior.

### O que mudou por baixo

- **O journal é lido em fluxo.** `diario::percorrer` entrega um registro
  de cada vez e guarda só o último cabeçalho. Antes, o boot lia o journal
  inteiro para a memória — e o heap do kernel era de 1 MiB, para uma
  partição de 16 MiB. Com a auditoria indo ao disco, o journal cresce
  depressa, e a suíte esgotou o heap.
- **O heap do kernel tem 8 MiB.** O anel da auditoria cheio é perto de
  meio MiB, e um registro de 64 KiB passa pelo heap algumas vezes; uma
  falha de alocação no kernel é pânico. Foram 4 MiB até os programas do IC,
  de uns 970 KiB, passarem inteiros por ele a cada lançamento — ver
  `kernel/src/heap.rs`.
- **Cada registro leva no máximo 16 KiB de auditoria.** O resto vai em
  registros só de auditoria antes dele, na ordem.
- **O plano de queda da bancada diz o tipo do registro**: a n-ésima
  operação, mensagem ou auditoria. O coletor grava registros de auditoria
  quando quer, e a n-ésima gravação de qualquer tipo deixaria de ser a
  mesma de uma corrida para outra.
- **O disco espera mais por uma descarga.** O teto de espera do
  virtio-blk era de cinco milhões de voltas — uns vinte milissegundos no
  ARM emulado em release, na CI. Com o journal gravando muito mais, uma
  descarga lenta do hospedeiro passou disso, e o disco foi desligado no
  meio da suíte. O teto passou a quatrocentos milhões; ainda é em voltas,
  e não em tempo.
- **O RTC do PC é lido com o índice e o valor juntos.** A auditoria lê o
  relógio a cada decisão, de qualquer fio, e um fio preemptado entre
  escolher o registrador do CMOS e lê-lo leria o valor de outro.

### As mutações do 7.5

| Mutação | Quem a mata |
|---|---|
| a reposição sem conferir a sequência, o tempo que volta ou o detalhe acima do teto | hospedeiro: *repor fora da regra é recusado* |
| a lacuna fora de sequência, ao contrário, ausente, com o elo errado, ou sem recomeçar a janela | hospedeiro: *o anel que perde deixa uma lacuna* |
| o tempo da cadeia sem piso; o boot sem continuar o que registrou | hospedeiro: *o tempo não volta*, *continuar com o que veio antes* |
| a codificação sem um campo; a leitura aceitando sobra, marca inválida ou texto que não é UTF-8 | hospedeiro: *o registro vai e volta*, *o registro estragado não se lê* |
| o percurso sem avançar o elo, ignorando a recusa, aceitando a sequência pulada; o escritor com a geração zero | hospedeiro: os casos do journal, *percorrer para no registro recusado* |
| o registro sem a auditoria; a gravada que não anda | suíte: *a decisão vai no registro da operação* |
| a decisão de uma credencial ou do quórum depois da gravação | suíte: *a decisão vai no registro da operação*, *dois de três*; bancada: *a queda em cada fronteira de uma operação* |
| a decisão de mensagem do administrador depois de executar | suíte: *o que não muda estado vai depois* |
| a decisão perdida no anel aceita; a lacuna fora do journal | suíte: *o que sai do anel é uma lacuna* |
| sem decisão, só o zero exigido; a decisão num registro anterior; sem teto por registro | suíte: *a lacuna*, *a decisão nunca vai antes* |
| o coletor sem gravar; gravar sem persistência; `durable` sempre verdadeiro | suíte: *o que não muda estado vai depois* |
| o tempo desde o boot na auditoria | suíte: *a decisão vai no registro da operação* |
| o boot ignorando a auditoria do journal, sem adotá-la, ou sem continuar o que registrou | bancada: *a auditoria sobrevive ao corte* |
| o journal recusado adotando a auditoria; a recusa sem `persistence.open` | bancada: *o journal recusado* |

Nenhuma sobreviveu. A do percurso que aceitava a sequência pulada
sobreviveu na primeira rodada — o caso do cabeçalho autêntico só tinha a
sequência repetida — e ganhou o caso que faltava.

## Como ficou (7.6)

### As duas regiões

A partição de estado tem duas regiões do mesmo tamanho e, no fim, 64
setores de reserva (o plano de queda da bancada mora no último; os dois
primeiros são, desde o B2, o selo da identidade do Duke — ver [A
identidade do Duke](#a-identidade-do-duke-b2)). O journal vive
numa delas. A outra é o journal de antes da última compactação, uma
compactação que não terminou, ou nada.

- **Qual vale.** O boot percorre as duas sem reaplicar nada. Vale a
  região **inteira** — a que começa com a abertura, ou com uma base que
  tem o fecho — de **última âncora maior**. Uma base sem fecho não é
  inteira, seja qual for o ponto em que parou. Duas inteiras com a mesma
  âncora não têm vencedora, e o boot recusa o journal.
- **A escolhida passa pela âncora como antes.** Escolher a região não
  confirma nada: a última âncora dela diante do contador do TPM decide,
  com as mesmas regras de sempre. A região antiga, com a âncora menor que
  o contador, é um disco atrasado — e é recusada se for a única que
  sobrou.
- **Nenhuma inteira, e registros no disco, é recusa.** Só o journal vazio
  em todas as regiões é um journal novo, ou uma criação a retomar.

### A base

A compactação escreve na outra região uma **base**: uma sequência de
partes (`BASE`) e um fecho (`BASE_FIM`), encadeadas como qualquer
registro, todas com a mesma âncora — a seguinte à do journal atual — e a
mesma geração. A base contém:

- **a história inteira da autoridade.** Cada registro de operação do
  journal atual, e cada parte de uma base anterior, entra com as entradas
  de autoridade dele — agentes, papéis, pessoas, credenciais, sessões,
  lápides — **e, na mesma parte, as decisões que as autorizaram**, os
  eventos da auditoria daquela operação, como `AUDITORIA_HISTORICA`. Uma
  mudança de autoridade nunca fica numa parte sem a decisão dela. As
  revogações nunca saem: são história, e a história é copiada inteira.
  Só a política é deduplicada: vai a do último registro que tinha uma.
- **as mensagens.** As lápides das mensagens que terminaram (o anel
  delas, com o mesmo teto), as vivas — a criada e, se foi entregue, a
  entrega —, e o próximo id. A tabela reposta da base é a mesma da
  memória, conferido no hospedeiro e na suíte. O corpo de uma mensagem
  copiado para a base é zerado depois de selado.
- **a auditoria.** Uma marca (`AUDITORIA_COMPACTADA`) com a sequência e o
  elo do último registro da cadeia antes dos que a base copia, e os
  registros gravados que ainda estão no anel. A cadeia reposta da base
  continua dali, com os mesmos elos, e se verifica.
- **o fecho**, com a instalação, os boots e as compactações.

### A ordem

1. **Só num ponto seguro**: no boot, depois da abertura e antes do
   registro de boot; ou no coletor. Nos dois, nenhuma operação está no
   meio, nada está pendente para o journal, e a ordem das gravações está
   na mão: o que está na memória é exatamente o que está no journal.
2. A região passou de três quartos.
3. As partes e o fecho são escritos na outra região, **uma descarga**, e
   **um avanço do contador** do TPM — que agora aponta para a base.
4. Só então a escrita passa para a região nova.

Uma queda em qualquer fronteira deixa valendo uma região inteira: antes do
fecho no disco, a antiga, ainda confirmada pelo contador; com o fecho no
disco e o contador sem avançar, a nova, que o boot completa como qualquer
registro escrito e não ancorado; com o contador avançado, a nova. Em
nenhum caso a antiga volta depois de o contador andar, e em nenhum caso a
geração muda.

### A região cheia

- **A base não cabe** na outra região: nada muda, a persistência continua
  disponível, a auditoria registra `persistence.compact` com o erro, e
  uma nova tentativa só depois de mais 64 registros.
- **Uma operação não cabe** na região: a gravação falha, e a operação
  também — ela não vale, a resposta diz que não ficou gravada, a
  persistência fica indisponível e nenhuma credencial administrativa
  passa. O boot seguinte, um ponto seguro, compacta, e volta. Não há
  caminho de recuperação à parte: é a mesma abertura, com as mesmas
  conferências.
- **Uma falha do disco ou do TPM** na compactação deixa a persistência
  indisponível, como numa gravação qualquer.

### A criação interrompida, com as regiões

A abertura vai na primeira região. Uma queda entre criar a âncora e o
primeiro registro deixa as duas vazias — ou a primeira com a abertura
cortada —, e o boot retoma a criação como no 7.4: o contador nunca passou
do nascimento. As quedas da criação continuam na bancada, agora sobre as
duas regiões.

### O que mudou por baixo

- **A âncora de uma base é a mesma em todas as partes.** O leitor confere
  a âncora seguinte de cada registro, exceto depois de uma parte, e recusa
  uma parte fora do começo da região ou um registro comum logo depois de
  uma parte.
- **O elo inicial de uma região vazia** é o do diário, e não zeros: o
  primeiro registro de uma região se encadeia a ele.
- **A abertura do boot roda inteira com a ordem das gravações na mão.**
  O coletor já roda no boot: com a persistência recém-disponível e a
  abertura ainda por gravar, ele gravava um registro só de auditoria
  antes dela — inofensivo até o 7.5, fatal com as regiões, porque uma
  região que não começa pela abertura não é inteira, e o boot seguinte
  recusava o journal. Pela mesma razão, o coletor podia compactar antes de
  as mensagens do journal serem adotadas. A bancada pegou a corrida, de
  forma intermitente, em quatro cenários.
- **O handler da serial não roda mais mascarado.** A resposta da serial
  era escrita no fio enquanto o handler executava, com a trava da serial
  na mão e as interrupções mascaradas. Uma operação administrativa pela
  serial que encontrasse a ordem das gravações com o coletor — no meio de
  uma compactação — esperava mascarada, com uma trava na mão, e o núcleo
  parava sem erro nenhum. A resposta agora é montada antes, como nas
  portas, e só a escrita no fio é mascarada; o modo post-mortem, sem heap,
  continua escrevendo direto. Esperar a ordem com as interrupções
  mascaradas é um erro na compilação de depuração.

### As mutações do 7.6

| Mutação | Quem a mata |
|---|---|
| a parte com a âncora seguinte; a base com a mesma âncora, ou subindo a geração; o fecho que confirma qualquer contador; montar aceitando a base | hospedeiro: *a base inteira vale e continua*, *a base não se monta como registro* |
| a base sem fecho inteira; qualquer primeiro registro inteiro; o fecho que não fecha (no percurso em fluxo) | hospedeiro: *a base cortada em cada setor não vale* — e o percurso em fluxo conferido contra a leitura inteira |
| a base fora do começo, ou um registro comum no meio dela | hospedeiro: *a base fora do lugar é recusada* |
| o empate escolhendo uma; a âncora menor escolhida | hospedeiro: *a escolha da região* |
| as regiões coladas, sem o limite, sem a reserva; o vazio com elo zero | hospedeiro: *as regiões dividem a partição*, *o vazio continua do começo* |
| a lápide de mensagem viva ou repetida aceita; as lápides sem teto; o próximo id que volta | hospedeiro: *a base repõe a mesma tabela* |
| a abertura sem a ordem das gravações | bancada: *o coletor não grava nada antes da abertura* |
| nenhuma região inteira, com registros, sem recusa | bancada: *a base sem fecho, sozinha no disco* |
| sempre a primeira região; o fecho sem contar a compactação | bancada: *a compactação do coletor sobrevive ao corte* |
| compactar com mudança pendente | suíte: *só num ponto seguro* |
| a base sem a decisão, sem a revogação de agente, com a primeira política, sem lápides, sem a entrega, sem o próximo id; a lápide ou o próximo id não repostos | suíte: *a região nova repõe o mesmo estado* |
| a base sem a marca da auditoria; o elo gravado que não anda | suíte: *o anel da auditoria dá a volta* |
| a base sem os eventos do anel | suíte: *a região nova repõe o mesmo estado* |
| sem a descarga antes do contador | suíte: a compactação descarrega exatamente uma vez |
| a região trocada sem conferir o contador; a falha da compactação sem fechar | suíte: *o contador trocado falha fechada* |
| a base que não cabe tratada como falha; a nova tentativa sem esperar depois de uma base que não coube | suíte: *a base que não cabe, a região que enche* |
| o boot sem compactar | bancada: *a região cheia falha fechada* |
| o coletor sem compactar; compactar só com a região cheia | suíte: *a região que enche, e o coletor* |
| a operação na região cheia sem fechar a persistência | suíte: *a gravação que falha*, *a região que enche* |

Nenhuma sobreviveu. A última foi **a nova tentativa logo depois de uma
base que não coube**, sem esperar mais 64 registros. O primeiro
relatório a deu como inofensiva; não é equivalente: sem a espera, o
coletor refaz a cada volta uma base que não cabe — regravando partes na
outra região — e põe na auditoria um `persistence.compact` com erro a
cada tentativa. Ganhou o caso: a suíte enche uma região até três
quartos, faz uma base que não cabe, e confere que ninguém tenta de novo
antes de mais registros, e que a compactação volta quando a base que não
coube é esquecida. A do próximo id conferido contra as vivas era
equivalente — o próximo de agora já está acima de todas, porque enviar e
restaurar o sobem —, e a conferência saiu do código.

Na primeira rodada sobreviveram nove: a abertura sem a ordem (a corrida
só aparecia por acaso), a primeira política, a marca da auditoria e o
elo gravado (o anel nunca dava a volta antes de uma compactação), a
descarga, o contador não conferido e a falha sem fechar (nenhum caso
separava o TPM do disco numa compactação), o fecho em fluxo e o teto das
lápides repostas. Cada uma ganhou o caso que faltava.

### O que fica para depois

- **A história da autoridade cresce sem fim.** A base carrega todas as
  mudanças de autoridade, com as decisões, desde a instalação — é assim
  que nenhuma revogação se perde. Só a política é deduplicada. Uma
  instalação com muitas operações acaba com uma base que não cabe na
  outra região: aí a compactação não acontece, a região enche, e a
  persistência fica indisponível — falhando fechada, mas parada. Com
  regiões de 8 MiB, são dezenas de milhares de operações. Resumir a
  história (o estado final de cada credencial, com a decisão que o fixou)
  é uma mudança de formato, e fica para quando for preciso.
- **A região cheia para tudo até o boot.** Uma operação que não cabe
  deixa a persistência indisponível até o próximo boot compactar; não há
  compactação em tempo de execução depois disso, porque a indisponível é
  justamente o estado em que nada é gravado. É o desenho conservador: o
  coletor compacta muito antes, a três quartos.
- **O TPM físico, a sessão autenticada no barramento e a proteção da
  credencial do contador** seguiram para o 7.7 — ver abaixo. A
  compactação não mudou nada disso: ela usa o mesmo contador, com o mesmo
  avanço.
- **A deduplicação depois do boot** continua como no 7.5.
- **`system.info` diz a região**, quanto dela está usado, de quantos
  setores, e quantas compactações houve.
- **O plano de queda** ganhou o ponto *depois da primeira parte*, o
  tamanho das regiões (para encher uma com poucas dezenas de operações) e
  duas bandeiras: o coletor não compacta, o boot não compacta.

## Como ficou (7.7)

### A sessão autenticada

Até o 7.6, a senha do contador ia em claro no barramento, numa sessão de
senha, a cada leitura e a cada avanço — e a resposta do TPM era aceita
como veio. Quem escutasse o barramento LPC/SPI aprendia a senha; quem
pudesse responder no lugar do TPM dizia o valor que quisesse. Agora todo
comando ao contador vai por uma **sessão HMAC salgada** (parte 1 da
especificação do TPM 2.0, capítulos 11, 19 e 21):

- **A chave de endosso.** A cada boot, o kernel cria a EK — ECC P-256, o
  modelo L-1 do TCG — na hierarquia de endosso. A área pública que volta é
  conferida byte a byte contra o modelo, e o ponto tem de estar na curva.
- **O sal.** Um par efêmero, um ECDH com a EK, e `KDFe(Z, "SECRET")`: só
  o TPM que tem a parte privada da EK chega ao mesmo sal. A chave da
  sessão é `KDFa(sal, "ATH", nonceTPM, nonceCaller)`.
- **O comando** leva `HMAC(chave da sessão ‖ senha, cpHash ‖ nonceCaller ‖
  nonceTPM ‖ atributos)`, com o `cpHash` sobre o código, os nomes das
  entidades e os parâmetros. A senha entra na chave do HMAC — sem os zeros
  do fim, como o TPM faz —, e nunca no fio.
- **A resposta** tem de trazer o HMAC do `rpHash` com o nonce novo do TPM
  e o `nonceCaller` deste comando. Uma resposta adulterada não confere;
  uma repetida de antes foi feita para outro nonce; uma forjada não tem a
  chave. Nenhuma das três vira valor.
- **A senha nova**, na definição do contador e do índice do nascimento,
  vai cifrada em AES-128-CFB (`KDFa(…, "CFB", nonces)`). Ver abaixo por
  que o CFB, que sozinho não tem integridade, está autenticado.
- **Os nomes dos índices** são calculados pelo kernel a partir dos
  atributos que eles têm de ter — inclusive o bit que o TPM liga na
  primeira escrita —, e não tirados do TPM. Um índice trocado por outro no
  mesmo número muda o nome, e o HMAC não confere.
- **Um erro fecha a sessão.** Um erro não gira os nonces, e não há como
  saber em que pé ela ficou: o comando seguinte abre outra.

**Não há autoridade nova.** A senha é a mesma do 7.4 — derivada da chave
do Duke, por um rótulo próprio —, o contador continua só um contador, e a
hierarquia do dono continua com a senha vazia, como antes. A sessão é
transporte: quem decide o que grava continua sendo o ponto de decisão, e
nada do modelo de autorização mudou.

### A senha nova cifrada, e autenticada

O CFB é só confidencialidade: um bit trocado no texto cifrado troca o
mesmo bit do que o TPM decifra. Sozinho, ele deixaria quem está no
barramento mexer, às cegas, na senha que o contador guardaria. Ele nunca
anda sozinho:

- **Cifrar e depois autenticar.** A cifra é feita antes do `cpHash`, e o
  `cpHash` é calculado sobre os parâmetros como vão no fio — o texto
  cifrado inteiro, o tamanho dele e o resto dos parâmetros (a área pública
  do índice). O HMAC do comando cobre o `cpHash` e o byte de atributos da
  sessão, onde está o bit que diz que o primeiro parâmetro vai cifrado.
  A chave do HMAC é a da sessão, salgada para a EK fixada: quem está no
  barramento não a tem.
- **O TPM confere antes de decifrar.** Um texto cifrado mexido, o bit da
  cifra tirado ou um byte da área pública trocado: o TPM responde
  `BAD_AUTH` na sessão — a falha do HMAC — e não define nada. Conferido
  contra o `swtpm`, byte a byte, em quatro lugares do comando; e, com o
  comando intacto, o mesmo TPM define e o contador funciona.
- **Nenhum par de chave e vetor se repete.** Os dois saem do `KDFa` com o
  `nonceCaller`, sorteado a cada comando, e o `nonceTPM`, que gira a cada
  resposta.
- **Um único caminho.** O módulo da cifra é privado do pacote `ancora`, e
  o único chamador é a sessão, que cifra e em seguida calcula o `cpHash`.
  Não há cifra de resposta em uso.
- **Por que não um AEAD.** O TPM 2.0 só oferece XOR e CFB para os
  parâmetros: AES-GCM ou ChaCha20-Poly1305 não são opção do protocolo. E
  não fazem falta: a integridade já vem do HMAC da sessão, numa composição
  que o próprio TPM impõe — com o HMAC sobre o texto às claras, o TPM
  recusa o comando, e a mutação que fazia isso morreu assim.

### A chave do TPM, fixada no journal

Salgar a sessão "com a EK" só protege se a EK for a do TPM certo. O
journal fixa a primeira que vê — na abertura, em todo registro de boot
(`CHAVE_DO_TPM`) e no fecho de cada base — e o boot confere a EK do TPM
com a fixada **antes de qualquer comando ao contador**. Outra EK é
recusada; um journal que fala de duas EKs, uma num registro e outra
noutro, também. Um journal de antes do 7.7 não tem EK fixada: o primeiro
boot do 7.7 a fixa.

**Isto não é identidade de hardware.** A fixação garante que o TPM é **o
mesmo** de quando o journal foi criado — e nada diz sobre se aquele
primeiro era um TPM genuíno. Nada confere a EK contra o certificado do
fabricante. Quem estiver no barramento **já no primeiro boot** pode
responder no lugar do TPM com uma chave sua, e ela fica fixada como se
fosse a do chip. A primeira confiança depende, então, de provisionamento
confiável: o primeiro boot numa máquina cujo barramento não foi mexido.
Da segunda em diante, a fixação vale.

### O TPM físico

- **TIS e CRB.** Além da FIFO do TIS — a dos TPMs discretos —, o kernel
  fala a CRB (*Command Response Buffer*), a interface dos TPMs de firmware
  (Intel PTT, AMD fTPM) e de muitos discretos novos: `cmdReady`, o
  comando no buffer, `START`, a espera, a resposta, `goIdle`. A interface
  sai do registro `INTERFACE_ID`, no mesmo endereço, `0xFED40000`. No ARM,
  a máquina `virt` só oferece o TIS.
- **`system.info`** diz a interface (`tpm_interface`) e o começo da EK
  (`tpm_ek`).
- **O que foi testado:** o `swtpm` (a `libtpms`, a implementação de
  referência da IBM) pelo `tpm-tis` e pelo `tpm-crb` do QEMU, nas duas
  arquiteturas; o mesmo journal criado por uma interface e aberto pela
  outra. **Não houve silício.** Ver o que fica para depois.

### O boot, passo a passo

1. As duas regiões lidas; a escolhida reaplicada; a EK fixada juntada.
2. Sem TPM: com journal, **recusado** — nada confirma que o disco é o
   atual, e um disco antigo com o TPM tirado da máquina traria de volta um
   agente revogado; sem journal, só indisponível, como antes.
3. A EK criada e conferida com a fixada. *(queda: depois da chave)*
4. O contador: o índice conferido, o valor lido pela sessão.
5. A decisão — a mesma do 7.4: confere, completar um avanço, recusar,
   criar.
6. O registro de abertura ou de boot, com a EK, gravado pelo protocolo de
   todo registro.

Do passo 3 em diante, **qualquer falha do TPM é recusa**: a EK que não é
a fixada, uma resposta que não confere, um transporte que não responde.
Até o 7.6, algumas delas deixavam a persistência só indisponível.

### O avanço que não se sabe se aconteceu

Gravar é escrever, descarregar, **incrementar** e **ler de volta** —
tudo pela sessão. Uma falha no meio não diz se o contador andou: a
resposta do incremento pode ter se perdido ou chegado adulterada. Uma
leitura autenticada, por uma sessão nova, decide:

| O contador está | O que acontece |
|---|---|
| onde o registro precisa | andou: a operação vale |
| um antes | não andou: o registro é **desfeito** no disco (o setor do cabeçalho zerado e descarregado), e a operação falha de verdade |
| em outro lugar, ou a leitura também falha | incerto: a operação não se diz gravada, a persistência fica indisponível, e o boot seguinte decide pela âncora |

Sem desfazer, uma operação recusada pelo TPM — uma credencial inválida —
ficaria no disco, e o boot seguinte completaria o avanço com a senha
certa: valeria uma operação respondida como falha.

### Contador, rollback e replay

| O que o boot encontra | O que acontece |
|---|---|
| o contador mais de um passo atrás do journal (o TPM devolvido a um estado anterior) | recusado |
| o contador um passo atrás | o último registro escrito e não ancorado — uma queda entre a descarga e o incremento —: o avanço é completado pela sessão. O que vale é o registro mais novo do disco, nunca um anterior |
| o contador à frente do journal (o disco devolvido a uma cópia, ou o contador avançado por fora) | recusado, e continua recusado nos boots seguintes |
| o valor do contador que não confere com a sessão (adulterado, repetido, forjado) | recusado |
| a credencial que o TPM recusa | nada anda, nada vale |
| outra EK, ou duas no journal | recusado |
| nenhum TPM, com journal | recusado |
| o TPM limpo | recusado (como no 7.4) |

Recusado, o journal fecha todas as credenciais — de pessoa e de agente,
igualmente; só a serial e o `sistema`, que não têm credencial, continuam.

### As quedas, em cada fronteira com o TPM

A bancada derruba a energia, numa compilação própria do kernel:

- **no boot**, depois de a EK conferida e antes do contador: nada mudou,
  e o boot seguinte abre com a mesma geração e a mesma EK;
- **na criação**, depois da EK, com o contador definido e nunca avançado,
  avançado e sem nascimento, com o nascimento e sem a abertura, e dentro
  da gravação da abertura: cada uma retomada ou completada;
- **em cada registro** — uma operação, uma mensagem, um só de auditoria
  —: antes da escrita, depois da escrita (que chegou ao disco, ou se
  perdeu sem a descarga), depois da descarga, **depois do incremento e
  antes da leitura de volta**, e depois do contador. O registro só de
  auditoria, desde que deixou de avançar o contador, não tem o ponto do
  incremento — ver *A auditoria e o contador*;
- **em cada compactação**, nas mesmas fronteiras, e depois da primeira
  parte.

Em todas, a operação vale exatamente quando o registro dela está no disco,
o boot seguinte abre, e nenhuma deixa valendo um estado anterior ao último
confirmado.

### Pessoa, agente e sistema

A sessão fica abaixo do journal: toda gravação, venha de quem vier, passa
pelo mesmo protocolo, pelo mesmo contador e pela mesma sessão. Nenhum
caminho grava sem ela, e nenhum ator tem um caminho próprio.

### O que mudou por baixo

- **As primitivas** são do RustCrypto: `sha2`, `hmac`, `aes`,
  `cfb-mode`, `p256`, todas sem `std` e sem os recursos padrão. O AES vai
  no *backend* em software: o código com SSE/NEON não compila para os
  alvos do kernel, que não usam registradores de ponto flutuante. Elas
  são otimizadas mesmo no build de depuração, como as do canal seguro: o
  ECDH de cada conexão levaria segundos.
- **A EK e a sessão ocupam vagas no TPM**, e um TPM tem poucas — o
  perfil do PC pede no mínimo três objetos e três sessões carregados. A suíte, que reabre a persistência muitas vezes,
  achou o defeito: um boot recusado deixava a EK e a sessão carregadas, e
  depois de poucas recusas toda conexão falhava. A âncora conectada no boot
  agora sai do TPM em toda saída que não fica com ela, e a de uma abertura
  anterior sai antes da nova.
- **A senha que termina em zeros.** O TPM tira os zeros do fim da senha
  antes de pô-la na chave do HMAC. A senha do contador é derivada da
  chave do Duke: em uma instalação a cada 256 ela termina em zero, e sem
  tirá-los nenhum comando ao contador passaria nela. Há um
  caso contra o `swtpm` com uma senha assim.

### As mutações do 7.7

No hospedeiro (`ancora`, contra o `swtpm` com um interposto no
barramento):

| Mutação | Quem a mata |
|---|---|
| a resposta sem o HMAC conferido; a comparação que só olha o tamanho | *a resposta adulterada*, *repetida* e *forjada é recusada*; *a comparação confere tudo* |
| o nonce do TPM que não gira; o `cpHash` sem os nomes; o `rpHash` sem o código do comando; o sal com o x trocado; a cifra sem o atributo que a anuncia | o TPM recusa o HMAC: *a âncora num TPM de verdade* e todos os que falam com ele |
| o nome do índice sem o bit de escrito | *a âncora num TPM de verdade* |
| a senha com os zeros do fim na chave do HMAC | *a senha entra no HMAC sem os zeros do fim*, *a senha com zeros no fim autoriza* |
| a EK fixada não conferida | *a âncora num TPM de verdade*, *cada TPM tem a sua EK* |
| a senha nova sem cifra | *a senha não passa pelo barramento* |
| a EK de qualquer modelo; a EK fora da curva | *a chave de outro modelo é recusada*, *a EK fora da curva é recusada* |
| o índice de qualquer tipo | *um índice de outro tipo no lugar é recusado* |
| o nascimento definido e nunca escrito lido como valor | *o nascimento definido e nunca escrito se completa* |
| o incremento sem a incerteza do nome | *o primeiro avanço sem resposta não deixa o nome velho* |
| o erro que não fecha a sessão | *a resposta adulterada*, *repetida* |
| a cifra depois do HMAC (o HMAC sobre a senha às claras); o HMAC sem o bit da cifra; a cifra só de parte do parâmetro; a cifra com os nonces trocados; o `cpHash` sem os parâmetros | o TPM recusa: *a âncora num TPM de verdade* e todos os que definem o contador |

No kernel (suíte e bancada):

| Mutação | Quem a mata |
|---|---|
| a releitura que confere não decide; o contador parado vira feito; a releitura que falha vira feito | suíte: *a resposta adulterada, repetida ou perdida não vira valor*, *a credencial inválida não grava*, *o contador incerto* |
| o registro não ancorado fica no disco | suíte: *a credencial inválida não grava, e o registro não ancorado é desfeito* |
| sem TPM, com journal, só indisponível | bancada: *o TPM tirado da máquina é recusado* |
| a EK fixada não vai ao conectar; o journal de duas EKs aceito; o fecho que não fixa; a entrada que não fixa; a fixada que não zera no começo da leitura | suíte: *a EK trocada é recusada, e o journal de duas EKs também* |
| a abertura sem a EK; o boot sem a EK; o fecho sem a EK | suíte: *aberta no boot*, *a EK trocada* — cada registro que fixa a EK a tem |
| a guarda que não solta a EK e a sessão; a abertura velha que não sai do TPM | suíte: depois de poucas reaberturas, o TPM sem vagas recusa o comando |
| a CRB nunca reconhecida | bancada: *o mesmo TPM pela CRB e pelo TIS* |

As cinco da cifra mostram, contra o TPM de verdade, que o HMAC que ele
confere é o do texto cifrado: não há como, deste lado, deixar o CFB sem
autenticação e ainda definir o contador. O caso *a senha cifrada mexida no
caminho é recusada* confere o outro lado — que o TPM recusa por
`BAD_AUTH` o texto cifrado, o bit da cifra e a área pública mexidos, sem
definir nada.

Sobrou uma, **equivalente**: na releitura de conferência, o contador num
valor que não é nem o esperado nem o anterior dado como avançado
(`Incerto` trocado por `Feito(v)`). Um `Feito(v)` com `v` diferente da
âncora do registro nunca confirma nada: o `confirmar` do escritor do
journal — numa gravação e numa compactação — recusa qualquer contador
que não seja o do registro, e a persistência fica indisponível, com o
registro no disco e o boot seguinte decidindo pela âncora: o mesmo estado
que o `Incerto` deixa. Só a mensagem muda — "o contador do TPM não foi
para a âncora do registro" em vez de "o próximo boot decide". Não é
lacuna de teste: a conferência que segura o comportamento é a do
`confirmar`, e ela tem os seus casos no hospedeiro (*só a âncora do
registro confirma*) e na suíte (*o contador trocado falha fechada*).

Na primeira rodada sobreviveram mais seis. Do hospedeiro: a conferência
do `continueSession` na resposta — equivalente, e saiu do código: os
atributos da resposta estão dentro do HMAC, e uma resposta que fecha a
sessão ainda traz um valor autêntico —, e três que ganharam caso: o
nascimento definido e nunca escrito (um erro ali recusaria o journal
para sempre depois de uma queda entre definir e escrever o índice), o
primeiro avanço sem resposta (o nome velho travaria todo comando
seguinte) e a EK fora da curva. Do kernel: a abertura sem a EK (a suíte
só a conferia depois de uma compactação) e a fixada que não zera (em
produção a abertura roda uma vez por boot; a reabertura no mesmo boot
agora começa do zero, conferido).

### O que fica para depois

- **O TPM físico em silício não foi testado.** Tudo rodou contra o
  `swtpm` — a implementação de referência —, pelo TIS e pela CRB do QEMU.
  Um chip de verdade pode diferir em tempo de resposta, em localidades, em
  quantas vagas tem; o código segue a especificação e os tempos dela, mas
  isso é o que se diz de todo driver antes do primeiro chip.
- **O endereço e o início do TPM.** O kernel procura o TPM no endereço de
  sempre, `0xFED40000`, e não lê a tabela ACPI `TPM2`. A CRB com início
  por registro é a única suportada: TPMs de firmware que pedem o início
  pelo ACPI (`_DSM`, ou o *start method* de alguns AMD fTPM) não
  respondem ao `START`. Numa máquina assim, sem journal a persistência
  fica indisponível; com journal, recusada — falha fechada, e nunca um
  estado anterior.
- **A EK é confiança na primeira vez, e não identidade de hardware.** O
  kernel não confere o certificado da EK contra a cadeia do fabricante,
  nem prende a âncora aos PCRs. Quem controlar o barramento **no primeiro
  boot** pode se fazer passar pelo TPM e ter a própria chave fixada; a
  primeira confiança depende de provisionamento confiável. Depois disso,
  não. A cadeia de certificados e os PCRs ficam fora deste incremento.
- **Quem controla o barramento ainda pode negar serviço.** Perder ou
  estragar respostas deixa a persistência indisponível ou o journal
  recusado: nunca um valor falso, nunca um estado anterior, mas parada.
- **O disco e o TPM devolvidos juntos.** Um TPM físico não deixa o NV
  voltar; o emulado deixa. Uma cópia do disco e do NV do TPM do mesmo
  instante, devolvidas juntas, é um estado coerente que nada distingue do
  atual. A bancada devolve o TPM sozinho — e ele é recusado.
- **O contador um passo atrás é completado**, e não recusado: é
  exatamente o estado de uma queda entre a descarga e o incremento, e o
  que vale é o último registro do disco — o mais novo, nunca um anterior.
  Um TPM devolvido exatamente um avanço, com o disco atual, passa por esse
  caminho e não restaura nada.
- **A senha da hierarquia do dono** continua vazia: um TPM cujo dono
  tenha senha não deixa definir o contador, e a criação é recusada como
  qualquer falha do TPM no boot.
- **Os PCRs não entram.** O contador está preso a uma senha, e não ao
  estado medido do boot. Prender a âncora a um boot medido é outra
  política, e outra fase.
- **A história da autoridade cresce sem fim**, como no 7.6: fora do
  escopo do 7.7.

## A auditoria e o contador

Até o 7.7, todo registro do journal avançava o contador do TPM — também
os só de auditoria, que o coletor grava a cada dois segundos quando há
atividade. Um TPM físico aguenta um número finito de escritas no NV, e
uma máquina ativa gastava ali um avanço a cada dois segundos sem que
nenhum estado de segurança tivesse mudado.

A separação:

```
journal / auditoria = persistência e histórico
contador do TPM     = monotonicidade do estado de segurança
```

### Quem avança o contador

Quem decide é o **tipo do registro**, no pacote `diario`
(`estado::tipo::avanca_a_ancora`), e não quem grava:

| Registro | Avança | Por quê |
|---|---|---|
| `ABERTURA` | sim | cria o journal e a instalação; a âncora começa nela |
| `BOOT` | sim | fixa a EK, conta os boots e carrega o piso do relógio |
| `OPERACAO` | sim | toda mudança de autoridade, com a decisão que a autorizou |
| `MENSAGENS` | sim | estado de mensagens: criada, entregue, confirmada, vencida, anulada — voltar atrás seria repetir ou ressuscitar uma mensagem |
| `BASE` / `BASE_FIM` | sim, uma vez | o fecho troca a região que vale; a região antiga tem de ficar recusada |
| `AUDITORIA` | **não** | leituras, recusas e o que mais o coletor grava: nenhum estado protegido muda |

Os caminhos que avançam o contador no código são três: a gravação de um
registro (`gravar_um`, agora só para os que avançam), o fecho de uma
compactação, e o boot — completar um avanço interrompido, criar a âncora
e dar o primeiro valor a um contador definido e nunca avançado. Os dois
últimos não mudaram.

**O caso ambíguo** foi o registro de boot. Ele não muda autoridade, e
nenhuma decisão de segurança lê o número de boots — a época das
mensagens vem da instalação, e não dele. Mas ele fixa a EK e carrega o
piso do relógio, que protege os prazos das mensagens contra um RTC
atrasado; e é um avanço por boot, e não um a cada dois segundos. Ficou
avançando: é a escolha conservadora, e o desgaste dele é desprezível.

### Como ficou garantido

- **O escritor** monta o registro só de auditoria na âncora de agora, e
  todo outro na seguinte. Um registro que avança só se confirma com o
  valor do contador lido de volta; um só de auditoria, só sem contador.
  Nenhum caminho do kernel consegue gravar uma transição protegida sem
  avançar: a confirmação sem contador a recusa.
- **O leitor** exige, depois de abrir o registro — o cabeçalho, com a
  âncora, é autenticado junto —, a mesma âncora do anterior num registro
  só de auditoria, e a seguinte em todo outro. Uma operação com a âncora
  repetida não é lida: um disco devolvido a antes dela não passaria
  despercebido por ela ter sido gravada sem o contador.
- **O julgamento** no boot não mudou: a última âncora do journal contra o
  contador. Os registros só de auditoria repetem a última âncora, e não
  mudam a conta.

### O que o contador não protege mais

**O rabo da auditoria.** Os registros só de auditoria gravados depois do
último registro que avançou o contador não têm a proteção dele: um disco
devolvido a uma cópia de antes deles — e depois daquele registro —
confere com o contador e é aceito. Perdem-se as leituras e recusas
daquele intervalo; nenhum estado protegido volta, e a decisão de cada
mudança de autoridade continua no registro da própria mudança, protegida.
O intervalo acaba no próximo registro que avança: o encadeamento do
journal faz cada registro novo comprometer os anteriores, e o registro
de boot seguinte ao corte já o fecha. O piso do relógio, do mesmo modo,
fica protegido até o tempo do último registro que avançou.

É o que a separação pede, e está nos testes: no hospedeiro, *o contador
protege o estado e não o rabo da auditoria* confere que a cópia de antes
da auditoria é aceita e a de antes da operação é recusada.

### A fronteira: o rabo da auditoria não traz estado

A perda do rabo da auditoria é aceita. O que ela nunca pode fazer é
permitir que um estado protegido anterior seja restaurado, aceito ou
reconstruído. Conferido assim:

| Propriedade | Por que vale | Quem confere |
|---|---|---|
| Nenhum estado protegido sai de um registro só de auditoria | Um registro `AUDITORIA` só leva eventos da cadeia e lacunas (`estado::so_de_auditoria`): o escritor não monta outro, e o leitor não o entrega — para nele. As mudanças pendentes de mensagens só saem em registros `MENSAGENS` | hospedeiro: *o registro de auditoria não carrega estado*; suíte: *um registro só de auditoria não carrega estado protegido* |
| Nenhuma decisão depende de um registro que pode sumir | A cadeia da auditoria só é lida por quem a guarda, pela persistência e pelos relatórios (`audit.tail`, `audit.head`, `audit.verify`). O ponto de decisão, as cotas e os arrendamentos não a leem | `cargo xtask invariantes`: *a auditoria só é relatada* |
| Nenhuma transição protegida se confirma por haver auditoria | Um registro que avança só se confirma com o contador na âncora dele — nem com o valor que a auditoria repete, nem sem contador | hospedeiro: *nenhuma transição se confirma pela auditoria*, *cada registro se confirma pelo seu tipo* |
| A auditoria não é prova de que uma transição aconteceu | O julgamento usa a última âncora, que a auditoria só repete: com ou sem auditoria no fim, o mesmo veredito. Um registro só de auditoria depois de um protegido não confirmado vai **no lugar** dele | hospedeiro: *a auditoria não prova transição* |
| O próximo registro protegido fecha o intervalo | Cada registro se encadeia ao anterior: depois de um que avançou, um disco devolvido a qualquer ponto do rabo antes dele é recusado | hospedeiro: *o próximo protegido fecha o rabo* |
| Rollback para antes de uma transição protegida é recusado | O contador está à frente do journal devolvido | hospedeiro: *o contador protege o estado e não o rabo*; bancada: *o rabo da auditoria volta com o disco, e o estado protegido não* |
| Repetir auditoria não avança nada | Um registro selado para um lugar e um elo não abre em outro: a leitura para nele, sem mudar âncora, geração ou estado; o contador só anda por registro que avança | hospedeiro: *a auditoria repetida não entra*; suíte: seis registros só de auditoria e o contador parado |

A bancada mostra a fronteira inteira, entre boots: um agente registrado e
revogado; a foto do disco logo depois da revogação, devolvida — aceita, o
rabo da auditoria some (dezenove registros duráveis, na última corrida), e
o agente **continua revogado**; a foto de antes da revogação, devolvida —
recusada, e o agente não volta.

**O relógio.** O piso do tempo lógico, no boot, é o tempo do último
registro — que pode ser só de auditoria. Num rollback do rabo, ele volta ao
do último registro que avançou: nunca abaixo do tempo de uma transição
protegida. Nenhuma decisão de autorização usa o tempo lógico; os prazos das
mensagens usam, e uma mensagem que vencesse no intervalo perdido, sem que o
vencimento tivesse sido gravado — uma transição, que avança —, continuaria
viva até o tempo passar de novo. É o mesmo rabo: nada que tenha sido
gravado como estado volta.

### Três propriedades, separadas

1. **Integridade e monotonicidade do estado protegido** — garantia de
   segurança, do TPM: nenhum estado protegido anterior volta.
2. **Persistência do journal** — propriedade de persistência: o que foi
   gravado e descarregado sobrevive a uma queda de energia, inclusive a
   auditoria.
3. **Monotonicidade do histórico da auditoria** — limitação assumida: o
   rabo depois do último registro que avançou pode sumir num rollback do
   disco para essa âncora. O TPM não volta a gastar escritas para cobri-lo.

### Os testes

- **Hospedeiro (`diario`)**: *a auditoria não gasta o contador* (quarenta
  registros só de auditoria entre a abertura e uma operação, e o
  contador anda duas vezes; e a classificação de cada tipo), *cada
  registro se confirma pelo seu tipo*, *o leitor exige a âncora do tipo*
  (uma operação, um boot ou uma mensagem com a âncora repetida não são
  lidos; um só de auditoria com a seguinte também não), *o contador
  protege o estado e não o rabo da auditoria*.
- **Suíte**: seis leituras, gravadas em seis registros só de auditoria,
  não mexem no contador; uma mensagem, uma operação de autoridade e o
  boot seguinte avançam um cada; o journal com os registros só de
  auditoria no meio abre, e a cadeia da auditoria confere.
- **Bancada**: o coletor grava registros só de auditoria entre dois
  cortes de energia, e a âncora não se move; o boot seguinte a avança
  uma vez, e uma operação, outra. As quedas num registro só de auditoria
  — antes e depois da escrita, depois da descarga, antes da confirmação —
  continuam valendo exatamente quando o registro está no disco.

### As mutações

| Mutação | Quem a mata |
|---|---|
| nenhum registro avança o contador; a abertura, o boot, a operação ou a mensagem sem avançar | hospedeiro: *a auditoria não gasta o contador* (a classificação de cada tipo) e os casos do journal que conferem a âncora |
| todo registro sem o contador, no kernel — a transição protegida confirmada sem avançar | suíte: a confirmação sem contador recusa, e as operações falham (dezenas de casos) |
| a auditoria volta a avançar o contador (no tipo, ou no kernel) | hospedeiro: *a auditoria não gasta o contador*, *cada registro se confirma pelo seu tipo*; suíte: a gravação da auditoria falha na confirmação |
| o leitor ignorando o tipo; aceitando a mesma âncora ou a seguinte; sem conferir a âncora | hospedeiro: *o leitor exige a âncora do tipo*, *a base fora do lugar é recusada* |
| montar sempre na âncora seguinte | hospedeiro: *a auditoria não gasta o contador*, *lê de volta o que escreveu* |
| confirmar com o contador um só de auditoria; confirmar sem ele um que avança | hospedeiro: *cada registro se confirma pelo seu tipo* |
| o registro só de auditoria sem contar como auditoria, ou como registro | suíte: *o que não muda estado vai no registro seguinte*, *aberta no boot* |
| o escritor montando, ou o leitor entregando, um registro só de auditoria com estado; qualquer entrada, ou um agente, cabendo nele; o conteúdo ilegível ou a entrada sem tipo passando por auditoria | hospedeiro: *o registro de auditoria não carrega estado* |
| uma leitura da cadeia da auditoria fora da persistência e dos relatórios — em `mensagens.rs`, ou num handler que não é relatório | `cargo xtask invariantes` |

Vinte e quatro, todas mortas; nenhuma equivalente. A da entrada sem tipo
sobreviveu na primeira rodada: o leitor entregava um registro só de
auditoria com uma entrada vazia — que o kernel recusaria ao reaplicar, sem
estado nenhum sair dele, mas a regra do leitor tem de ser exata. Ganhou o
caso.


## Decisões tomadas

- **Âncora:** o TPM 2.0, com um contador monotônico de NV; o `swtpm` como
  TPM de desenvolvimento no QEMU, nas duas arquiteturas. Desde o 7.7,
  falado por uma sessão HMAC salgada com a EK, e a EK fixada no journal.
- **Sem TPM, com journal:** recusado (até o 7.6, só indisponível). Nada
  confirma que o disco é o atual, e indisponível deixaria as credenciais
  de um disco antigo valendo.
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

## O armazém e o journal de estado

O armazém (ver [`ARMAZENAMENTO.md`](ARMAZENAMENTO.md)) morou no journal de
estado na fase 8, com os arquivos inteiros nos registros. Agora ele tem
uma partição própria, com um journal de metadados do mesmo pacote
`diario`, e o journal de estado guarda dele uma entrada só, de tamanho
fixo:

```text
ARMAZEM_CONFIRMADO [id do volume, setores, setores do journal dele, âncora, elo]
```

— qual registro do journal do armazém vale. Ela vai num registro do tipo
`ARMAZEM`, que avança o contador do TPM e leva junto a auditoria da
execução do comando: **é o ponto de commit** de um lote do armazém. A
base de uma compactação do estado leva essa entrada e mais nada do
armazém; as entradas de antes (`ARQUIVO_GRAVADO` e as outras da fase 8)
são recusadas como de um formato anterior.

Uma escrita que não é do journal de estado não chega à janela dele: o
driver tem uma janela por partição, fixadas no boot pela GPT, e o
`xtask` confere que só a persistência usa a de estado e só o volume a do
armazém.

A bancada ganhou um ponto de queda, `LoteNoVolume` (17): o lote inteiro
no volume — blocos e registro, descarregados — e a confirmação ainda não
começada. O cenário que cai ali confere que o boot seguinte não confirma
o lote, que os blocos voltam livres e que o próximo lote grava; o que cai
em cada fronteira da gravação de estado confere que o lote vale inteiro
exatamente quando o registro de estado está no disco; e o do volume
devolvido a uma fotografia anterior confere que ele é recusado sem
derrubar o estado de autoridade.

**A restauração de uma cópia** (B5, ver "A cópia de segurança e a
restauração" em [`ARMAZENAMENTO.md`](ARMAZENAMENTO.md)) usa a mesma
entrada e nenhuma nova: o armazém restaurado vai ao volume como uma
**base** na outra região do journal dos metadados — o mecanismo da
compactação do volume —, e um registro `ARMAZEM` com `ARMAZEM_CONFIRMADO`
apontando o fecho dela, e a auditoria da execução, é o ponto de commit.
Até ele, a região de antes é a que vale; depois, a nova — um registro só,
como um lote. A cópia não leva nada do journal de estado: restaurá-la não
volta o contador, não desfaz uma revogação nem repõe uma lápide. Os pontos
de queda dela são `CopiaNoMeio` (34), `RestauracaoConferida` (35),
`RestauracaoNaPrimeiraParte` (36), `RestauracaoNaBase` (37) e
`RestauracaoGravada` (38), mais os de dentro da gravação de estado; a
bancada `cargo xtask copia` cai em cada um e confere que o boot seguinte
tem a árvore inteira de antes ou inteira a da cópia — a da cópia
exatamente quando o registro está no disco.

## As chaves de assinatura (ICP-3)

As chaves de assinatura das identidades (ver [ICP.md](ICP.md), *A chamada
assinada*) moram no journal de estado, sem um armazenamento à parte —
o mesmo registro cifrado, a mesma âncora do TPM, a mesma compactação.
No ICP-3, em duas entradas — desde o ICP-5, a semente não vai mais ao
disco, e a entrada da criação é o objeto selado no TPM: ver [O cofre das
chaves no TPM](#o-cofre-das-chaves-no-tpm-icp-5); o que segue sobre a
lápide, a reposição estrita e o disco velho continua valendo:

```text
CHAVE_CRIADA (33) [dono, nome, domínio, criada em ms, semente (32)]
CHAVE_MORTA  (34) [dono, nome, estado (1 destruída, 2 anulada), domínio, criada em ms, pública (32)]
```

- **A criação grava antes de responder.** `key.create` vai num registro
  de operação, com a decisão do gate no mesmo registro, e a semente
  cifrada com ele — só ali: o conteúdo é montado num vetor do tamanho
  exato, e zerado depois. Sem persistência, nenhuma chave nasce: um boot
  não a traria de volta. A gravação que falha desfaz a criação inteira,
  sem lápide — o nome não foi de chave nenhuma.
- **A lápide é permanente.** `key.destroy`, `key.revoke` e a revogação do
  dono (`person.revoke`, `agent.revoke`) gravam `CHAVE_MORTA`, sem a
  semente; nenhum registro a desfaz, e o nome não volta, nem para o dono
  registrado de novo. Na operação administrativa, a lápide de cada chave
  do dono vai **antes** da revogação, no mesmo registro: reposta, a
  revogação não acha chave viva, e não anula de novo.
- **A reposição é estrita.** No boot, cada chave viva volta com a mesma
  privada, e cada lápide volta. A criação sobre uma lápide, ou com outra
  pública, é um erro do journal.
- **A compactação larga a semente da morta.** A base leva a viva com a
  semente e a morta só como lápide: a semente de uma chave destruída não
  chega à região nova. Fica na região velha até ela ser reescrita — não
  há apagamento criptográfico por chave; a região velha continua cifrada
  com a chave do journal.
- **O disco velho não ressuscita nada.** Cada registro de chave avança o
  contador do TPM: uma fotografia de antes da destruição, devolvida ao
  disco, é recusada pela âncora, e com o journal recusado nenhuma
  credencial entra — a chave destruída não assina por ela.
- **A destruição que não ficou gravada** fica — a privada já foi apagada
  da memória — até o boot, como toda revogação que não ficou gravada, e
  a resposta diz isso; a persistência indisponível não deixa nada assinar
  até lá. Depois do boot, a chave volta viva: a destruição não foi
  respondida como feita.

Na bancada de persistência, as chaves sobrevivem ao corte de energia — a
viva assina igual, com a mesma privada; a destruída volta destruída e não
assina —, a fotografia de antes da destruição é recusada, e o disco de
agora, de volta, abre com ela destruída. A queda em cada fronteira da
gravação da criação e da lápide vale exatamente quando o registro está no
disco: a criação que não valeu deixa o nome livre, e a destruição que não
valeu deixa a chave viva, assinando igual.

## O cofre das chaves no TPM (ICP-5)

O ICP-5 tira a semente das chaves de assinatura do disco. A custódia
continua do kernel — a semente nasce do gerador dele, a privada mora na
memória dele e a assinatura sai dele, pelo gate, como no ICP-3 —; o que
muda é o repouso: o journal guarda um **objeto selado no TPM** da
máquina, que só esse TPM abre, e só enquanto a chave estiver viva.

### O objeto selado

- **O primário** é um primário de armazenamento na hierarquia do dono —
  ECC P-256 com o modelo de SRK do TCG: `fixedTPM`, `fixedParent`,
  `sensitiveDataOrigin`, `userWithAuth`, `noDA`, `restricted`, `decrypt`,
  AES-128-CFB, `unique` zerado —, recriado por `TPM2_CreatePrimary` a
  cada operação do cofre e tirado do TPM no fim dela: um TPM tem três
  vagas de objeto, e o `TPM2_Create` e o `TPM2_Load` precisam de uma além
  da EK e do primário. O mesmo TPM dá sempre o mesmo primário; o nome
  dele é anotado no boot, e cada operação confere que é o mesmo — outro é
  o TPM limpo, ou trocado, e nada se sela nem se abre nele.
- **O selado** é um *keyedhash* filho do primário, criado por
  `TPM2_Create` com a semente como dados: `fixedTPM`, `fixedParent`,
  `adminWithPolicy` e `noDA`, sem `userWithAuth` — nenhuma senha o abre
  — e com a política da geração como `authPolicy`. O journal guarda o
  bloco privado — cifrado e autenticado pelo TPM, sob a semente do
  primário —, o `unique` e a geração; o resto da parte pública é refeito
  pelo kernel.
- **A política da geração** é um `TPM2_PolicyNV` sobre o índice de
  geração (`0x0180_D0E2`): o valor do contador igual à geração em que o
  objeto foi selado. O `TPM2_Unseal` só passa numa sessão de política em
  que o `TPM2_PolicyNV` passou — e ele só passa com o índice nesse valor.
- **No barramento**, a semente nunca anda em claro: no `TPM2_Create` ela
  é o primeiro parâmetro, cifrado pela sessão salgada com a EK fixada; no
  `TPM2_Unseal` ela volta cifrada pela sessão de política, salgada
  também, e a resposta é autenticada antes de decifrada. O
  `TPM2_PolicyNV` se autoriza com a senha do índice — derivada da chave
  do Duke, como a do contador da âncora —, pela sessão HMAC da âncora.
- **`noDA` no primário e no selado:** nenhuma autorização errada neles
  conta para o bloqueio do TPM. O selado não tem senha — só a política —,
  e o primário não tem senha do dono; um TPM bloqueado por outro uso não
  trava o cofre.

### A morte de uma chave e o índice de geração

Toda morte de chave — `key.destroy`, `key.revoke`, a revogação do dono —
avança a geração em três passos, com a ordem das gravações na mão:

1. o registro da operação: a lápide, as vivas **seladas de novo para a
   geração seguinte** e `SELAGEM_PENDENTE(g+1)` — tudo num registro só,
   que a âncora confirma;
2. o índice de geração incrementado no TPM, e lido de volta;
3. o registro `SELAGEM_CONFIRMADA(g+1)`.

O índice nunca anda antes de os selados novos estarem confirmados no
journal. Depois do passo 2, todo objeto selado na geração `g` — o da
morta e os das vivas de antes — deixa de abrir, inclusive numa cópia
velha do disco: a cópia tem os selados de `g`, e o TPM está em `g+1`. Um
passo 2 ou 3 que falha deixa a persistência indisponível: o registro da
operação está no journal, e o boot seguinte completa o avanço, ou o
confirma.

### O boot

Com o journal confirmado pela âncora, o boot abre o cofre: recria o
primário, define o índice de geração se ele não existe — num journal que
nunca falou de geração —, e concilia a geração que o journal diz com a
do TPM:

| journal | TPM | o boot |
|---|---|---|
| sem geração | — | segue com a do TPM |
| confirmada `C` | `C` | segue |
| confirmada `C`, pendente `C+1` | `C+1` | confirma o avanço |
| confirmada `C`, pendente `C+1` | `C` | completa o avanço |
| qualquer outra coisa | — | recusado |

Um índice que sumiu do TPM com o journal falando de geração é recusado:
um índice novo nasceria em outro valor. Depois, cada chave viva é
aberta — `TPM2_Load`, `TPM2_PolicyNV`, `TPM2_Unseal` —, e a pública que
sai da semente tem de ser a da chave. A primeira que não abre recusa o
journal, com o motivo dela; a chave fica fechada — `key.sign` responde
*a chave está selada no TPM e não foi aberta neste boot* —, e **nenhuma
semente de outro lugar** entra no lugar: nem a de uma entrada antiga,
nem a da memória, nem a de cópia nenhuma.

### O formato

```text
SELAGEM            (9)   o registro da selagem
CHAVE_SELADA       (35)  [dono, nome, domínio, criada em ms, pública (32),
                          geração (8), unique (32), bloco privado]
SELAGEM_PENDENTE   (36)  [geração]
SELAGEM_CONFIRMADA (37)  [geração]
LIMPEZA_PENDENTE   (38)  []
LIMPEZA_FEITA      (39)  []
```

`CHAVE_CRIADA` (33), a entrada com a semente, é o formato de antes: o
kernel ainda a lê, para migrar, e não a escreve mais. A compactação leva
`SELAGEM_CONFIRMADA`, a limpeza se ela ainda falta, cada viva como
`CHAVE_SELADA` e cada morta como lápide; o registro do boot leva
`SELAGEM_CONFIRMADA` também.

### A migração das chaves antigas

Um journal de antes do cofre é um com um boot completo que nunca falou de
geração. Um sem boot completo nenhum é uma criação interrompida — por
este kernel ou pelo de antes —, e não tem chave nenhuma: uma chave só
nasce depois do registro de boot. O primeiro boot sobre um journal de
antes do cofre:

1. repõe as chaves antigas com a semente da entrada antiga, e abre o
   cofre;
2. sela cada uma na geração atual, e grava um registro `SELAGEM` com
   `SELAGEM_CONFIRMADA`, as `CHAVE_SELADA` e `LIMPEZA_PENDENTE`;
3. compacta: a região nova tem só os objetos selados;
4. zera a partição de estado fora do journal de agora — a região velha,
   com as entradas antigas, e o que sobrou desta —, menos a reserva do
   fim, que é da bancada;
5. grava `LIMPEZA_FEITA`.

Uma queda em qualquer passo é retomada no boot seguinte. A entrada
antiga e o selado da mesma chave, juntos no journal, repõem a chave
**fechada** — o objeto selado é a única origem da privada —, e o cofre a
abre; a limpeza pendente é refeita até o registro do fim. Uma
compactação que não cabe deixa a limpeza pendente no journal, para o
boot seguinte.

### O que o cofre não é

O TPM é mecanismo de custódia em repouso, não autoridade: não decide
quem assina — a política decide quem pode `key.sign`, e o gate decide
cada assinatura, como no ICP-3 —, não guarda chave de assinatura nem
assina, e não aparece na política. `key.read` diz `"custody":"kernel"` e
`"seal":"tpm"` — e nada do objeto selado, da sessão ou do TPM.

### Os testes

- **No hospedeiro**, contra o swtpm com o interposto no barramento
  (`ancora/tests/swtpm.rs`, quinze novos): selar e abrir; o mesmo
  primário em dois boots; o selado que não abre noutro TPM
  (`TPM_RC_INTEGRITY`), nem no mesmo TPM depois de limpo; o mexido
  recusado, também com a geração trocada; a semente que não passa pelo
  barramento, nem no `TPM2_Create` nem no `TPM2_Unseal`; a resposta do
  `TPM2_Unseal` mexida ou repetida, recusada; a geração que anda mata os
  selados velhos (`TPM_RC_POLICY`), também depois de reiniciar; o índice
  recriado não ressuscita nada; a geração definida e nunca avançada se
  completa; a senha errada da geração não abre nem bloqueia; o bloqueio
  do TPM não trava o cofre — e, de controle, um primário sem `noDA`
  trava —; a política é a que o TPM calcula, por uma sessão de teste e o
  `TPM2_PolicyGetDigest`; os atributos do primário e do selado são os
  pedidos, bit a bit; as aberturas que falham não ocupam o TPM.
- **Na suíte**, dez casos novos, e o do journal das chaves invertido —
  nenhuma semente no journal, e o selado da viva lá, antes e depois da
  compactação: a semente não chega ao disco — em registro decifrado
  nenhum, de nenhuma região, nem em claro na partição — nem ao
  barramento; a morta não volta de uma cópia antiga do disco — a
  destruída, a anulada e a do dono revogado, cada morte avançando a
  geração uma vez —; o selado que não abre falha fechado, com o motivo; o
  primário que não é o do boot não sela nem abre; sessenta e quatro
  vivas, com a morte de uma e a revogação de um dono; tudo ao mesmo
  tempo — dois assinantes, criações e mortes, compactações —; a
  revogação do dono enquanto o boot abre as chaves; a migração das
  antigas; a antiga cujo selado não abre fica fechada, sem a semente de
  antes; e o Principal da chave selada, o mesmo depois que o cofre a
  reabre e depois que a morte de outra a sela na geração seguinte.
- **Na bancada de persistência**: as chaves seladas diante de outro TPM —
  a EK fixada recusa, e nada assina —; a queda entre os três passos de
  uma morte, em sete pontos; a queda em cada passo da migração, em dez,
  com o disco conferido depois — nenhuma semente em registro decifrado de
  região nenhuma, nem em claro, nem entrada do formato de antes, e zeros
  fora do journal —; e a queda em cada fronteira da compactação, agora
  com uma chave selada que volta e assina igual. Os cenários de antes —
  a queda na criação e na destruição de uma chave, as chaves que
  sobrevivem ao corte — passam com o cofre. A queda na criação da âncora
  achou a migração disparando numa criação interrompida (ver *A
  migração*); a CI 324 a pegou no ARM e no x86.

### As mutações

Uma de cada vez, numa worktree à parte, com o que a pega: os testes do
hospedeiro do `ancora`, a suíte do x86 só com os casos `chaves:`,
`persistencia:` e `tpm:` — e os `icp:` da chave —, e os cenários da
bancada de persistência do cofre. O controle, sem mutação, passa em
tudo. As vinte reprovam:

| forma | o que muda | quem a pega |
|---|---|---|
| a semente em claro | o `TPM2_Create` sem a cifra do parâmetro | o barramento, no hospedeiro e na suíte |
| a semente cifrada só pela chave do Duke | a criação no formato de antes, com a semente no journal | treze casos da suíte |
| sem `fixedTPM` | o selado sem o bit | o TPM recusa o `TPM2_Create` (`TPM_RC_ATTRIBUTES`): treze testes do hospedeiro; na suíte, nenhuma chave nasce |
| sem `fixedParent` | o selado sem o bit | o mesmo |
| o Unseal sem proteger a resposta | a semente volta em claro | o barramento, no hospedeiro e na suíte |
| o primário de outro TPM aceito | o cofre não confere o nome do primário do boot | o caso do primário que não é o do boot |
| sem `TPM2_PolicyNV` | o selado abre pela senha vazia, em qualquer geração | oito testes do hospedeiro; a morta que volta de uma cópia antiga |
| a geração não avança | a morte sem o passo 2 | dois cenários da bancada e sete casos da suíte |
| a geração avança antes dos selados novos | o passo 2 antes do registro | a queda antes da escrita de uma destruição: o boot recusado, todas as chaves perdidas |
| a migração sem zerar | a limpeza sem os zeros | a bancada da migração e o caso dela |
| a migração sem limpeza | nem compactação forçada, nem zeros | o mesmo |
| a compactação leva a entrada antiga | a base com a semente junto do selado | a bancada da migração e três casos |
| a semente antiga fica | a entrada do formato de antes e um selado que não abre: a privada antiga não sai | a antiga cujo selado não abre |
| a falha do Unseal ignorada | a chave fica como estava, e o boot segue | o selado que não abre, e a antiga |
| o primário sem `noDA` | o primário conta para o bloqueio | o TPM não começa os comandos (`TPM_RC_RETRY`): treze testes do hospedeiro |
| o selado sem `noDA` | o selado conta para o bloqueio | os atributos pedidos — sem senha, o selado não erra autorização nenhuma |
| `key.sign` sem o gate dele | a permissão de ler basta | quatro casos (ICP-3, ICP-4c) |
| a revogação ignorada | a revogação do dono não anula as chaves | cinco casos |
| a declaração sem âncora | a decisão de qualquer um ancora | a declaração ancorada |
| a chave de outro dono | o nome resolve fora do dono | oito casos, e cada chave é um Principal |

### As medidas

Na suíte do x86 em depuração, com o swtpm — um TPM de software: um TPM
de verdade é mais lento em cada comando —, o caso das sessenta e quatro
vivas e as operações do cofre sozinhas, dezesseis vezes cada — o x86
em duas rodadas, a suíte inteira e o caso sozinho; a compactação
depende do resto do estado da região, e o ARM a mediu depois de outros
quarenta casos:

| | x86 | ARM |
|---|---|---|
| criar 64 chaves (cada uma selada, gravada e ancorada) | 1060 a 1490 ms | 1150 ms |
| a morte de uma: 63 seladas de novo, um registro, o índice | 220 a 280 ms | 260 ms |
| a revogação de um dono: 8 mortas e 55 seladas de novo | 270 ms | 240 ms |
| a reposição inteira, com o cofre abrindo 55 | 2360 ms | 2560 ms |
| a compactação com 55 | 1030 ms | 2390 ms |
| o primário recriado (`TPM2_CreatePrimary`) | 2,5 ms | 2,5 ms |
| selar (`TPM2_Create`) | 3,8 a 5,6 ms | 3,1 ms |
| abrir (`TPM2_Load`, `TPM2_PolicyNV`, `TPM2_Unseal`) | 5,0 a 6,9 ms | 7,5 ms |

No boot, o registro que diz o cofre aberto diz quanto ele levou; na
bancada, com uma chave viva: 40 ms no x86 e 20 ms no ARM, o kernel de
depuração; sem chave nenhuma, de 0 a 30 ms. A reposição da suíte, que
refaz a região inteira, é quase toda a leitura do journal: as 55
aberturas são de 280 a 410 ms dela. O `key.sign` não muda: a privada continua na
memória do kernel, e a assinatura não fala com o TPM.

O kernel de produção (release) cresceu 58 432 bytes de código no x86
(+1,7%) e 59 300 no ARM (+2,1%); com os dados, 57 544 (+0,8%) e 63 484
(+1,6%). A imagem do x86 que o iniciador carrega passou de 4440 para
4504 KiB. Os programas não mudaram — nenhum fonte deles nem das
bibliotecas deles —, e têm exatamente o tamanho do ICP-4e; a raiz
continua com 160 MiB.

### Os riscos que ficam

- **O mesmo TPM com o disco.** Quem tem o disco — a chave do Duke está
  nele, ou, desde o B2, o selo dela, que este TPM abre — e o mesmo TPM
  satisfaz a política: o índice está na geração das vivas, e a senha dele
  deriva da chave do Duke. As vivas de agora abrem; as mortas, não. O
  cofre não mede o boot: nenhum PCR entra na política.
- **A janela do passo 2.** Se o avanço do índice falha depois do registro
  da operação, uma cópia de antes da morte ainda abriria a morta, no
  mesmo TPM, até o boot seguinte completar o avanço.
- **O custo.** Cada morte de chave sela de novo todas as vivas e gasta
  três escritas de NV — o contador da âncora duas vezes, e o índice de
  geração uma.
- **A limpeza da migração** depende de a compactação caber; enquanto não
  cabe, as entradas antigas ficam na região velha, pendentes.

## Fases e estado

| Fase | O quê | Estado |
|---|---|---|
| 7.0 | A bancada: partição de estado, TPM em toda máquina, relógio, vários boots com corte de energia, fotografia e restauração da partição | feita |
| 7.1 | Escrever no disco (só a partição de estado, com `FLUSH`), o TPM pelo TIS, o RTC | feita |
| 7.2 | O journal: registros autenticados, geração, âncora, piso do relógio | feita |
| 7.3 | O estado administrativo durável (R1–R6) | feita |
| 7.4 | Mensagens persistentes, e as fronteiras entre o disco e o TPM | feita |
| 7.5 | Auditoria persistente | feita |
| 7.6 | Compactação e disco cheio | feita |
| 7.7 | O que restar da âncora (TPM físico, sessão autenticada no barramento) | feita |
| ICP-3 | As chaves de assinatura no journal: a semente, a lápide, a compactação | feita |
| ICP-5 | A semente selada no TPM, presa ao índice de geração: a morte em três passos, a migração das antigas | feita |
| B1 | O estado da atualização A/B: a ativa, a candidata e o piso de geração, no journal | feita |
| B2 | A identidade do Duke nascida no primeiro boot, selada no TPM, antes do journal | feita |

## A atualização A/B

O estado da atualização — a imagem **ativa**, a **candidata** se há, e o
**piso**, que é a geração da ativa — é estado protegido como os outros:
mora no journal, e a âncora o protege. Ver
[`ATUALIZACAO.md`](ATUALIZACAO.md).

```text
ATUALIZACAO        (40)  o registro de uma decisão do boot: a linha de base,
                         a confirmação, o desfazimento. Avança o contador, e
                         não a geração administrativa
ATUALIZACAO_ESTADO (41)  [ativa: slot, geração, manifesto, versão,
                          candidata: a mesma forma, ou vazia, motivo]
```

A instalação e a desistência pelo quórum `system.update` levam a entrada
`ATUALIZACAO_ESTADO` no registro da operação (`OPERACAO`), que avança a
geração administrativa como toda operação de autoridade. A última entrada
vale; a base da compactação leva a de agora.

O piso não tem índice de NV próprio. A confirmação — a candidata que vira a
ativa, e o piso que sobe com ela — é **um** registro, que avança o contador
**uma** vez: não há uma janela em que o TPM diga um piso e o journal outro.
Um disco devolvido a um journal de antes da confirmação é um journal atrás
da âncora, recusado como qualquer outro; e, sem o journal, a autoridade
não existe, para a versão velha nem para a nova.

Na bancada de persistência, o x86 boota pelo firmware, e o kernel vem do
slot A: o primeiro boot de um kernel vindo de um slot, numa máquina sem
estado de atualização, grava o registro da **linha de base**, e os
cenários que contam os registros do journal um a um contam este também.
Ele é um registro de estado, que leva a auditoria pendente — a abertura
da persistência, entre outras — se chega ao journal antes do coletor; e
quem chega antes depende do tempo. Por isso o cenário da queda num
registro só de auditoria sobe um boot comum antes do que cai: depois da
abertura, nele, só o coletor grava. No ARM a bancada boota pelo
`-kernel`, de fora de um slot, e não há linha de base.

## A identidade do Duke (B2)

Tudo o que a persistência guarda é cifrado ou autorizado por derivações da
chave do Duke — a cifra do journal, a senha da âncora, a do índice de
geração, as do armazém. Numa máquina de produção a chave nasce no
primeiro boot, selada no TPM, e não mora no journal: o journal só abre com
ela. Ver [`kernel/src/selo.rs`](../kernel/src/selo.rs),
[`ancora/src/identidade.rs`](../ancora/src/identidade.rs) e "A identidade
do Duke" em [`OPERACAO.md`](OPERACAO.md).

- **Onde mora.** Nos dois primeiros setores da reserva do fim da partição
  de estado, uma cópia em cada: o ponto da EK em que nasceu, a pública, e
  o objeto selado — o `unique` e o bloco privado que o TPM cifrou —, com
  um SHA-256 contra o setor estragado. Fora das regiões do journal, e fora
  da limpeza do cofre, que zera só até a reserva. Só a persistência
  escreve ali, pela janela de estado, como no journal; o selo pede.
- **O objeto selado.** Sob o mesmo primário do cofre, `fixedTPM` e
  `fixedParent`, sem política e com a senha vazia: a política de geração
  não serve, porque a senha do índice deriva da própria chave. Nenhum
  índice de NV novo.
- **A ordem no boot.** A identidade é estabelecida antes de `persistencia::abrir`,
  com uma conexão própria com o TPM, que sai inteira dele antes de a
  persistência conectar a dela; o `policy.load` continua o primeiro
  registro da auditoria de um boot, e o `system.identity` — o nascimento,
  o reparo de uma cópia, a recusa — vem depois dele.
- **Sem identidade.** A persistência não abre. Com journal na partição —
  alguma região começando por um registro, pela magia, sem a chave — ela
  é **recusada**, e não só indisponível: o que o journal guarda pode ser
  uma revogação que agora não se lê, e as credenciais fecham como diante
  de qualquer journal que não se confirma. Sem journal, é indisponível.
- **Nascer.** Só numa instalação nova: nenhum selo inteiro, nenhum
  journal, e nenhum índice do Duke no TPM — a âncora, o nascimento, a
  geração. Uma identidade nova por cima de estado que dependa de outra
  seria uma máquina que não abre o próprio estado.
- **A ordem das descargas.** A chave só entra em uso — a âncora e o
  nascimento definidos no TPM, o primeiro registro do journal — depois de
  a primeira cópia do selo estar descarregada no disco; a segunda é
  descarregada antes de a persistência abrir. Um disco que perde o cache
  no corte não deixa os índices do Duke no TPM sem um selo que os abra:
  sem a descarga, a máquina ficaria recusada para sempre, como a de outra
  instalação. A bancada da identidade corta a energia num disco assim — o
  disco hostil, abaixo — na descarga de cada cópia e na primeira do
  journal, e o boot seguinte nasce de novo ou abre a cópia descarregada.

A abertura do selo custa, a cada boot, uma conexão a mais com o TPM — a
EK, a sessão salgada, o primário — e o `TPM2_Load` com o `TPM2_Unseal`; o
nascimento, uma vez na vida da máquina, o `TPM2_Create`, a abertura de
volta e duas escritas descarregadas. O log do boot diz quanto levou: no
x86, com o kernel de depuração e o swtpm — um TPM de verdade é mais lento
por comando —, o nascimento levou 70 ms, e a abertura, de 40 a 60 ms.

O kernel de produção (release) cresceu 33 336 bytes nos segmentos
carregáveis no x86 (+0,81%) e 26 088 no ARM (+0,75%), contra o B1
(`d48d31b`). O iniciador e os programas não mudaram — nenhum fonte deles.

### As mutações do B2

Uma de cada vez, no repositório, com o que a pega: os testes do
hospedeiro do `ancora` (e o do `provisionar`, no `xtask`), a suíte do x86
só com os casos `identidade:`, e os cenários da bancada da identidade. O
controle, sem mutação, passa em tudo. As trinta reprovam:

| forma | o que muda | quem a pega |
|---|---|---|
| a cópia sem o resumo conferido | a leitura da área não confere o SHA-256 | o bit trocado e a escrita cortada, no hospedeiro |
| os zeros depois do privado; o reservado; a versão | a leitura não confere cada um deles | o resumo refeito não salva o formato errado |
| duas cópias inteiras e diferentes abrem a primeira | sem a recusa das divergentes | a tabela inteira, e o teste delas |
| uma cópia inteira sem TPM tenta abrir | sem a recusa antes da abertura | a tabela; e a bancada, sem o TPM: o motivo que a máquina diz é outro |
| a cópia que falta não é reparada | a decisão sem o reparo | a tabela, e o teste do reparo |
| a cópia ilegível não impede o nascimento | sem a recusa do setor que o disco não lê | a tabela, e o teste dela |
| nasce por cima do journal | a decisão sem o journal | a tabela, e o teste dele |
| nasce no TPM de outra instalação | a decisão sem os índices do Duke | a tabela, e o teste deles |
| a chave em claro no `TPM2_Create` | sem a cifra do parâmetro | o barramento, no hospedeiro e na suíte |
| o `TPM2_Unseal` sem proteger a resposta | a chave volta em claro | o barramento, no hospedeiro e na suíte |
| o selado sem `fixedTPM` | o objeto sem o bit | o TPM recusa o `TPM2_Create` (`TPM_RC_ATTRIBUTES`): doze testes do hospedeiro |
| o selado sem `noDA` | o objeto sem o bit | os atributos pedidos, e mais nove testes do hospedeiro |
| o selado administrado pela senha | sem `adminWithPolicy` | ninguém troca a senha da identidade; os atributos pedidos |
| a chave aberta sem a pública conferida | o boot não confere a chave com a área | a pública trocada, na suíte |
| a cópia estragada não é reparada no boot | sem a reescrita | a suíte, e a bancada (uma cópia estragada) |
| o nascimento grava só a primeira cópia | sem a segunda escrita | a suíte (as duas cópias, a concorrência) e a bancada (o primeiro boot) |
| o nascimento não vai à auditoria | sem o registro | a bancada, o primeiro boot |
| a recusa não vai à auditoria | sem o registro | a bancada, sem o TPM e a reinstalação: a recusa lida pela serial |
| o journal não conta na decisão | `ha_journal` sempre falso | a suíte, e a bancada (as duas cópias estragadas recusam por outro motivo) |
| o TPM não conta na decisão | os índices do Duke sempre ausentes | a bancada, a reinstalação: o disco novo no TPM de antes nasceria |
| o nascimento sem a abertura de volta | o selado não é aberto e conferido antes de gravar | a suíte: o nascimento cujo `TPM2_Unseal` de volta se perde |
| a área gravada sem descarga | a escrita sem o `FLUSH` | a bancada, o cache do disco: o corte na primeira descarga — a do journal — leva as duas cópias com os índices já no TPM, e a máquina fica recusada como a de outra instalação. A suíte não a pega: o disco dela não perde o que foi escrito |
| sem identidade e com journal, a persistência só indisponível | a recusa vira indisponibilidade | a suíte, e a bancada (sem o TPM) |
| a EK da área não é conferida na abertura | a conexão aceita qualquer EK | a suíte (a EK de outro TPM, a área com outra EK) e a bancada (o disco clonado) |
| as duas cópias no mesmo setor | o setor da segunda é o da primeira | a suíte (o reparo) |
| a chave adotada por cima da que está em uso | sem a recusa da adoção | a suíte (nenhuma por cima; a concorrência) |
| a persistência abre antes da identidade | a ordem do boot trocada | a bancada, os boots seguintes: a persistência indisponível no boot do nascimento. O primeiro boot sozinho não a pega — ele confere a identidade e a auditoria, e não a persistência |
| a imagem de produção leva a chave do Duke | o `provisionar` põe a privada na raiz | o teste do hospedeiro do `provisionar` |

Três delas não tinham testemunha no primeiro commit do B2 (`c9cbb55`), e
o desenho da campanha as achou antes de ela rodar: a área gravada sem
descarga — nenhum cenário perdia o cache do disco no nascimento —, a
recusa sem auditoria — numa máquina sem identidade nenhum agente entra, e
ninguém lia o registro — e o nascimento sem a abertura de volta. As três
testemunhas entraram no `0e4e3ae`, e a campanha rodou sobre ele. A
testemunha da recusa achou um defeito: o motivo de "journal sem selo"
tinha 103 bytes, e o detalhe da auditoria guarda 96 — chegava cortado.

No ARM, contra a bancada pelo AAVMF e a suíte do aarch64, de novo as
cinco que dependem da arquitetura — o disco hostil atrás do NVMe, o
barramento do TPM pelo `tpm-tis-device`, a auditoria lida pela serial, a
reinstalação e a ordem do boot: a chave em claro no `TPM2_Create`, a
recusa sem auditoria, o TPM fora da decisão, a área sem descarga e a
persistência antes da identidade. O controle passou; as cinco reprovaram
pelos mesmos casos e cenários do x86.

## O disco hostil

O arquivo de um disco emulado não perde nada: o que o emulador escreveu
está no cache do hospedeiro e sobrevive à morte dele. Uma gravação
confirmada antes da descarga passaria do mesmo jeito que uma confirmada
depois — e a descarga antes de avançar o contador e de confirmar é o que
separa as duas. A bancada põe atrás do NVMe da máquina um disco que se
comporta como um de verdade, e pior: um servidor NBD dela mesma
([`xtask/src/disco_hostil.rs`](../xtask/src/disco_hostil.rs)), com um
cache de escrita volátil, erros de mídia por faixa e respostas retidas.

| Cenário | O disco | O que se confere |
|---|---|---|
| o disco que perde o que não foi descarregado | cada escrita fica no cache até a descarga; o corte — numa escrita ou numa descarga exata, pelo próprio servidor — perde tudo, ou uma parte sorteada com semente fixa, como um SSD sem capacitor | doze gravações pedidas de uma vez, e a energia corta no meio: no boot seguinte a persistência abre, cada gravação confirmada está lá, cada uma sem confirmação está inteira ou não está, e a auditoria e o armazém conferem. Quatro rodadas |
| o erro de mídia no journal | toda escrita no journal volta com erro de mídia, que o NVMe conclui como falha | a gravação que precisava do registro não é confirmada, a persistência se declara indisponível com o motivo, o `disk.info` conta o erro com o último, e a máquina segue — recusando o que mudaria o estado; com o disco são, o boot seguinte abre, sem a gravação |
| o disco que para de responder | toda escrita no journal fica sem resposta, para sempre | o driver espera o prazo do disco — trinta segundos, pelo contador de ciclos — e desliga o controlador; a gravação não é confirmada, o `disk.info` diz `alive` falso e o tempo esgotado; com o disco são, o boot seguinte abre, sem a gravação |
| o cache do disco no nascimento da identidade (`cargo xtask identidade`, numa máquina de produção nova) | o corte na descarga da primeira cópia do selo, na da segunda — antes de gravar — e na primeira do journal, perdendo tudo | o arquivo fica sem cópia, com a primeira, ou com as duas; o boot seguinte nasce de novo — nada dependia da chave sorteada — ou abre a cópia descarregada e repara a outra, com a persistência de pé; nunca recusa |

Os cortes são determinísticos: o servidor corta na n-ésima escrita ou
descarga, e a parte guardada sai de uma semente escrita no cenário — a
mesma rodada perde os mesmos setores em toda execução.

E o corte é definitivo. Quando o servidor corta, a máquina ainda está
viva — a bancada a mata depois —, e o cliente NBD do emulador, ao ver a
conexão cair, abre outra sozinho no pedido seguinte. Até a investigação
da CI 359, o servidor a aceitava: a máquina cortada seguia gravando com o
disco de volta, e a rodada do corte na quarta escrita terminava com dez
das doze gravações confirmadas — pelo menos nove delas depois do corte. Nenhuma
promessa foi quebrada (toda confirmada voltou), mas o cenário conferia
uma máquina que não tinha perdido a energia. Agora o servidor fecha sem
negociar toda conexão que chega entre o corte e o `religar` da bancada,
que vem depois de ela matar o emulador; a mesma rodada termina com uma
gravação confirmada e três reconexões recusadas, e os dois cenários que
cortam pelo gatilho — este e o do nascimento da identidade — conferem que
a máquina cortada não teve o disco de volta.

E o fim do disco hostil espera a conexão em curso. O emulador que a
bancada mata deixa no socket o que já tinha mandado — uma escrita, uma
descarga —, e o servidor ainda o atende antes de ver o fim da conexão:
uma descarga ali grava o cache no arquivo. Até o #314, o fim do disco
(`DiscoHostil::drop`) só avisava o servidor e voltava, e nada garantia que
a conexão já tinha acabado: uma descarga atrasada podia cair no arquivo
depois de o cenário seguinte zerar o estado, e devolver à partição de
estado um pedaço do journal velho, diante de um TPM novo. Agora o fim
espera o fio do servidor sair, com a conexão em curso acabada e o arquivo
fechado. Quem solta o disco mata o emulador antes — a máquina, declarada
depois do disco, cai antes dele —, e a partida que sobe a máquina mas não
consegue preparar o canal dela a mata antes de devolver o erro: solta
viva, ela seguraria a conexão, e o fim esperaria para sempre. O teste do
hospedeiro (`o_fim_espera_a_conexao_em_curso`, em
[`xtask/src/disco_hostil.rs`](../xtask/src/disco_hostil.rs)) faz o papel
do emulador — uma escrita, cuja resposta lê, uma descarga, e o socket
fechado sem ler a resposta dela —, com o servidor segurando a descarga
antes de aplicá-la, e
confere que, quando o fim volta, o fio já saiu e a descarga já está no
arquivo, e que o arquivo zerado depois continua zerado. A mutação N229 —
o fim sem a espera — está em [`SDK.md`](SDK.md).

A suspeita veio da CI 439: na bancada da atualização do ARM, o cenário
seguinte ao do disco que falha ("duas instalacoes ao mesmo tempo...")
teve o journal recusado no primeiro boot, sobre um estado zerado — a
escrita do slot negada com `DENY_REVOCATION`, a decisão 34. Mas não foi
isso o que aconteceu ali: as contas que o cenário do disco imprimiu,
depois de matar o emulador e antes de soltar o disco, já tinham a conexão
encerrada (`conexoes: 1, encerradas: 1`) — o servidor só conta o fim
depois de atender tudo o que a conexão trouxe, e não há outra. O motivo
da recusa daquele boot não chegou ao log da CI: no ARM, a serial é o
canal, e o log do kernel fica no anel dele. Aqui, os dois cenários em
sequência no ARM, com o fim novo, passaram nas duas rodadas, e no x86,
na bancada inteira — ainda com o fim antigo —, também: a recusa da CI 439
não se reproduziu.

Para a próxima dizer o porquê, a bancada pergunta. Toda resposta da
máquina — pela serial ou por uma porta de agente — que diz
`DENY_REVOCATION` marca a máquina, e o fim dela — o corte de energia do
cenário (`Ligada::cortar_a_energia`), ou o `Drop` da `Ligada`, em
[`xtask/src/persistencia.rs`](../xtask/src/persistencia.rs) —, antes de
matar o emulador, pede o `system.info` pela serial e imprime o estado e o
motivo da persistência: `[persistencia]   uma resposta disse
DENY_REVOCATION; a persistencia da maquina: refused (<o motivo>)`. O
cenário da CI 439 corta a energia antes de soltar a máquina: perguntar só
no `Drop` seria perguntar a uma máquina morta — a primeira rodada daqui,
com a pergunta só no `Drop`, num cenário da persistência que também corta
a energia antes ("o journal recusado..."), imprimiu "a maquina nao
respondeu (... Broken pipe ...)". É pela serial porque ela não é
credenciada: com o journal recusado, o gate recusa toda credencial —
também o `system.info` pela porta do agente —, e a serial ainda lê. A
pergunta tem cinco segundos; a máquina que não responde, ou que já tinha
acabado, diz isso na mesma linha. O corte que a bancada do enlace faz no
meio do cenário (`Ligada::cortar`) não pergunta. Nos cenários que
provocam a recusa de propósito, a linha sai quando uma resposta deles diz
`DENY_REVOCATION` — nem todos recebem uma —, e só repete o que eles
conferem. A marca é uma só para a bancada, e as bancadas da persistência e
da atualização a esquecem no começo de cada cenário. O teste do hospedeiro
(`a_recusa_de_revogacao_pede_o_motivo`) confere que a resposta da CI 439
marca, que a recusa por permissão não marca, e que o motivo sai inteiro,
com as vírgulas dele; as mutações N230 e N231 estão em [`SDK.md`](SDK.md).

A bancada espera cada boot pelo andamento da máquina, e não por um prazo
do total: segue enquanto chega algo novo na serial humana, nos contadores
dos discos pelo QMP — bytes e operações de leitura, de escrita e de
descarga, de todos os discos — ou no canal; desiste quando nada muda por
dois minutos, e acaba no teto de cinco, andando ou não (`JANELA_SEM_ANDAR`
e `TETO_DO_BOOT`, em `xtask/src/persistencia.rs`). No boot seguinte a um
reinício, com o canal já aberto, os sinais só contam depois que o boot de
antes para de responder, e o canal não conta: o que chega nele é lido
pela pergunta que espera a resposta — no ARM, só os discos dizem que a
máquina anda, e o console do firmware desse boot não vai para a serial
do cenário. Era um prazo de
noventa segundos, e na CI 408 reprovou dois boots que andavam, num runner
sem CPU: um no iniciador, conferindo o kernel de 15,8 MB — que ele lê do
slot um mebibyte por vez, somando o resumo de cada pedaço antes de ler o
seguinte, e cada pedaço é uma leitura nova no disco; no prazo, o disco
tinha lido 16,4 MB e estava ocioso havia 0,28 s —, e outro no kernel,
antes de ligar os outros núcleos, com o disco ocioso havia 1,1 s. Uma
máquina parada, como o firmware da CI 413 — a serial muda e o disco
ocioso havia 253 segundos —, continua reprovando, em dois minutos. O
trecho mudo mais longo de um boot que anda é o do firmware antes do
console: medido aqui, com o firmware do Ubuntu 24.04 (edk2 2024.02; a CI,
no Ubuntu 26.04, usa o 2025.11), o OVMF escreve o primeiro byte na COM1
seis segundos depois de o emulador abrir o QMP, e o AAVMF, meio segundo
depois. No fim, a bancada diz o maior intervalo sem sinal novo que um boot
que atendeu teve, para a janela se refazer com o número da CI.

Um boot da bancada que não atende diz, além do fim da serial, o que o
emulador diz de si pelo QMP — se roda, onde está cada processador e se
parado num `hlt`, e quanto cada disco leu e escreveu, com há quanto tempo
está ocioso —; se o `swtpm` vive, e o fim do log dele; no x86, o fim do
log de depuração do firmware; e, sobre o disco hostil, o que o servidor
atendeu. O log do `swtpm` fica no nível 1, o dos erros: do nível 2 em
diante ele escreve cada comando e cada resposta do TPM inteiros, em
hexadecimal — medido com o 0.7.3 do Ubuntu 24.04: os bytes de um
`TPM2_GetRandom` saem nele; a CI usa o 0.10.1 —, e com eles o que o TPM
guarda para a máquina. O log de depuração do firmware é o `debugcon` da
porta 0x402, onde o EDK II escreve as mensagens de depuração. O OVMF da
CI, do Ubuntu 26.04, é uma compilação de release — `BUILD_TYPE ?=
RELEASE` no `debian/rules` do pacote, e o `DEBUG_ON_SERIAL_PORT`
comentado —, e o do Ubuntu 24.04, medido, não escreve nada nele, nem na
0xe9: com eles o log fica vazio, e o que o firmware diz sai no console,
na COM1, que já está no fim da serial; um firmware de depuração escreve
nele, e o boot que não atende mostra o fim. O ARM não tem `debugcon`: o
AAVMF escreve o console na PL011, que na bancada é o canal, e o que a
espera da partida e a da queda leem do canal antes de a máquina atender
vai para a serial do cenário. Na CI 359, o primeiro boot de uma rodada parou no iniciador,
lendo o kernel do slot, e a serial não dizia mais que isso: se o
processador esperava o disco, se o disco tinha um pedido pendurado, ou se
o emulador inteiro tinha parado. A falha não se reproduziu aqui (três
execuções inteiras do cenário, 24 boots); a próxima ocorrência diz qual
das três foi.

## O firmware parado da CI 436

Na CI 436 (`05e0383`), no job da atualização do x86, o cenário "a queda em
cada fronteira do desfazimento" reprovou num boot que não atendeu: nada
novo na serial, nos discos nem no canal por 120 segundos, e o último sinal
4 segundos depois da partida. O QMP disse `running`, o processador 0 em
`0x6c7e370`, com as interrupções ligadas e fora de um `hlt`, e os outros
três parados num `hlt` em `0x6c650d1`; os dois discos — o `ide0-hd0` e o
`disco0`, o mesmo arquivo — com 79 leituras e 152 KiB cada um, ociosos
havia 121 segundos; o `swtpm` vivo, com o log vazio; o `debugcon` vazio,
de um firmware de release. Na serial, só a abertura do console do
firmware: as limpezas de tela e as duas trocas de tamanho, 240×56 e
160×42 — os 146 bytes que um boot que anda escreve antes do `BdsDxe:
loading`.

**Que boot era.** Pelos horários do log, o primeiro boot do cenário, e não
o que segue uma queda planejada dele: cada máquina que a bancada liga
publica os programas antes (`comando_qemu` → `codigo::publicar`, as
linhas do cargo no log), e entre o fim do cenário de antes e a reprovação
houve uma só, às 05:25:53, com a reprovação 125 segundos depois — os 120 da
janela e os 4 do último sinal. Antes dele, a última máquina do cenário de
antes foi cortada (`SIGKILL` no QEMU e no `swtpm`), e o `zerar_o_estado`
zerou a partição de estado e o armazém, restaurou o slot A e o controle, e
recriou o diretório do TPM.

**O que a queda deixa, e o que o firmware lê.** Numa queda planejada, o
kernel com a feature `quedas` lê o plano no último setor da partição de
estado, avisa `{"queda":N}` no canal no ponto — numa linha só, depois de
esperar, até meio segundo, que outro núcleo termine a resposta que estiver
escrevendo na serial: os outros núcleos continuam, e um aviso escrito por
cima de uma resposta não se lê (a queda no meio da coleta da auditoria sob
carga, com a serial pedindo sem parar, o mostrou) —, e congela — ou, no ponto
antes da confirmação e com a bandeira 5 do plano, entra em pânico —; a
bancada lê o aviso e corta a energia — o `SIGKILL` no QEMU e no `swtpm` —,
apaga o plano e liga outra máquina: outro processo do QEMU, outro `swtpm`
sobre o mesmo diretório e o mesmo arquivo de disco. O firmware lê, no boot
seguinte:

- o código, só de leitura;
- as variáveis da UEFI, que são uma cópia nova do modelo a cada máquina que
  a bancada liga (`firmware_uefi`): nada passa de uma máquina para outra
  por elas — só os reinícios dentro de um mesmo processo, as tentativas da
  atualização e o `system.reboot`, as mantêm;
- o TPM, pelo TIS — o `TPM2_Startup`, os PCRs e o registro do boot medido
  —, com o NV como o `swtpm` o gravou por último; o volátil morre no corte;
- o disco, pelo IDE e — até a ordem de boot, abaixo — pelo virtio: a GPT,
  cada partição sondada pelos drivers de sistema de arquivos — a de estado
  e a do armazém também —, a FAT da ESP e o `BOOTX64.EFI`;
- o `fw_cfg`: a ordem de boot, a ACPI, o SMBIOS;
- os consoles: a COM1 e a COM2, que é o canal do agente — o aperto de mão
  da bancada escreve nela as linhas do `agent.ping` enquanto o firmware
  roda, e elas chegam ao `ConIn` dele como teclas, sem um `ESC` nem uma
  tecla de função, que levariam ao menu;
- e o gerador de números (`virtio-rng`), que o OVMF liga sempre, e a placa
  de rede, com a pilha de rede inteira do firmware por cima dela, que o
  `EfiBootManagerConnectAll` do BDS liga porque a máquina não diz uma ordem
  de boot ao firmware — até a CI 438: ver [A ordem de
  boot](#a-ordem-de-boot), abaixo.

O que um corte pode deixar num estado incomum para o firmware é só o disco
— o journal e o controle como o kernel os deixou — e o NV do TPM; as
variáveis, nunca. No boot que parou na CI 436, nem isso: o estado tinha
sido zerado e o TPM recriado antes dele.

**Onde estavam os processadores.** Com o firmware da CI — o `ovmf-generic`
2025.11-3ubuntu7.3, baixado do arquivo do Ubuntu — e a máquina da bancada,
o QEMU 8.2 daqui põe as imagens do DXE nos mesmos endereços que o 10.2 da
CI: os processadores estacionados param aqui também em `0x6c650d1`, que é
`CpuDxe+0xd0d1`, logo depois do `hlt` do `CpuSleep` (`hlt; ret`), com as
interrupções desligadas. E `0x6c7e370` é `Metronome+0x370`: o salto de
volta do laço que lê o relógio da ACPI (`pause; jmp`), dentro do
`gBS->Stall`. Os módulos que esperam com uma cópia própria desse laço —
o `Tcg2Dxe`, o `AtaAtapiPassThruDxe`, o `Ps2KeyboardDxe`, o `CpuDxe` e o
núcleo do DXE — teriam o processador neles: a espera pelo TPM ou pelo
disco IDE não estava ali. Os que esperam pelo `gBS->Stall` são outros: a
`VirtioLib` dos drivers virtio (o `VirtioFlush`, que espera o dispositivo
sem prazo), o `PciSioSerialDxe`, o `BdsDxe`, o `VirtioSerialDxe` e o iPXE
da placa de rede.

**Quando.** Aqui, com o firmware da CI, os dois discos chegam a 79 leituras
e 155 648 bytes aos 4,6 segundos — exatamente onde os da CI pararam —, e o
IDE lê os setores seguintes 0,26 segundo depois, antes do `BdsDxe:
loading`: o fim do `PlatformBootManagerAfterConsole` — a pilha de rede
ligada sobre a placa, as opções de boot gravadas nas variáveis, as medidas
do `Tcg2Dxe` — e o BDS antes de carregar a opção de boot.

**A causa, reproduzida.** O firmware da CI, subido sozinho até o `BdsDxe:
loading` na máquina da bancada, com os estímulos da espera da bancada — o
QMP a cada segundo, o aperto de mão na COM2 —, um TPM novo e uma cópia nova
das variáveis a cada boot: 300 boots sem parar nenhum, de 4,8 a 7,1
segundos até a opção de boot. Com a CPU disputada por quatro processos
ocupados, como num runner sem folga: o boot 27 parou como o da CI — o
processador 0 em `0x6c7e370`, os outros em `0x6c650d1`, os mesmos 146 bytes
na COM1 — e a memória e as pilhas ficaram guardadas. O diagnóstico novo,
sobre elas:

```
CPU#0 em 0x6c7e370: Metronome+0x370 (a imagem em 0x6c7e000, de 0xa00 bytes; o nome pelo arquivo do firmware); na pilha: Metronome+0x3cf, DxeCore+0x283, DxeCore+0x2ea, DxeCore+0x2ef, VirtioRngDxe+0x709, Ip4Dxe+0x94df, DxeCore+0x5a71, DxeCore+0x5bea
CPU#1, CPU#2 e CPU#3 em 0x6c650d1: CpuDxe+0xd0d1 (a imagem em 0x6c58000, de 0x16d80 bytes; o nome pelo arquivo do firmware); na pilha: CpuDxe+0x9e38
```

O `Stall` é o do `VirtioFlush` dentro do `GetRNG` do `VirtioRngDxe`
(`VirtioRngDxe+0x709`, o retorno da chamada ao `gBS->Stall` no laço que
compara o índice usado do anel com o esperado), e quem pediu os números foi
o `Ip4Dxe` (`Ip4Dxe+0x94df`): o `PseudoRandom` da pilha de rede — o
`LocateProtocol` do `EFI_RNG_PROTOCOL` e um `GetRNG` de 4 bytes por
algoritmo —, no `Start` do driver, chamado do `ConnectAll` do BDS. O anel
do gerador mostra o resto: o índice disponível e o usado valem 14 — o
dispositivo respondeu a tudo —, e o `GetRNG` de fora espera o 13 (o `r15`
dele). Um segundo `GetRNG` entrou durante a espera do primeiro — só o
`GetRNG` põe pedidos nesse anel, e no meio do `Stall` só roda a
notificação de um evento de temporizador, num TPL acima; quem chama o
gerador no firmware da CI são os drivers da pilha de rede —, usou o mesmo
descritor 0, e foi respondido; o laço do primeiro — `while
(*Ring->Used.Idx != NextAvailIdx)` — não acaba mais. É um defeito do EDK II: o
`VirtioRngGetRNG` sem proteção de TPL. O EDK II o corrigiu a partir do
`edk2-stable202602` — o `GetRNG` sobe ao `TPL_NOTIFY` em volta do pedido
—; o OVMF do Ubuntu 26.04, o da CI (2025.11-3ubuntu7.3), não tem a
correção, nem o 2024.02 daqui. A parada pede um temporizador da rede no
meio de um `GetRNG`, e o `GetRNG` espera a resposta do laço principal do
QEMU: com a CPU do hospedeiro disputada, a janela cresce. A CI 413 parou no
mesmo trecho do boot — depois do console, antes de carregar a opção de
boot, no boot que seguia um reinício pedido pelo kernel, em que o BDS liga
a pilha de rede de novo —; é provável que tenha sido o mesmo defeito.

Nem a bancada, nem o estado que uma queda deixa, nem o kernel entram nisso:
o firmware para antes do iniciador, sobre um estado zerado. A bancada
continua reprovando o boot que não atende — não há segunda tentativa, que
esconderia a falha. O que mudou, depois da segunda ocorrência, na CI 438,
foi a máquina: ela não dá mais o gatilho — ver [A ordem de
boot](#a-ordem-de-boot), abaixo.

**As rodadas aqui.** O firmware da CI sozinho: 300 boots sem a CPU
disputada, nenhum parado; 200 com ela, um parado — o boot 27, acima. O
cenário inteiro, com o firmware daqui (2024.02): três rodadas, 27 boots,
nenhum parado — e nele a parada não tem como acontecer: no OVMF 2024.02
do Ubuntu 24.04, só o `VirtioRngDxe` e o shell citam o `EFI_RNG_PROTOCOL`,
e a pilha de rede não o chama; no 2025.11 da CI, chamam o `Ip4Dxe`, o
`Ip6Dxe`, o `Udp4Dxe`, o `Udp6Dxe`, o `TcpDxe`, os dois DHCP, o DNS, o PXE,
o HTTP e o iSCSI. O QEMU e o `swtpm` daqui não são os da CI (8.2.2 e 0.7.3
aqui; 10.2.1 e 0.10.1 lá), e a parada saiu com o QEMU daqui: o defeito é do
firmware.

**O diagnóstico novo.** O boot que não atende diz agora em que módulo cada
processador está, e os valores da pilha dele que caem no código de uma
imagem ([`xtask/src/firmware.rs`](../xtask/src/firmware.rs); o que ele
imprime está no README, na serial da bancada). Conferido em máquinas
paradas de propósito pelo QMP — no meio do firmware daqui
(`AtaAtapiPassThruDxe`, lendo o disco, e o `CpuDxe` dos estacionados), no
iniciador (`iniciador.pdb`, pelo CodeView, com o `virtio-net.efidrv` do
iPXE na pilha), e no meio do firmware da CI, com os estacionados em
`CpuDxe+0xd0d1` —, e na memória da máquina que parou, acima. As mutações
N210–N220 estão em [`SDK.md`](SDK.md).

### A ordem de boot

**A segunda vez.** Na CI 438 (`9174cb8`), o mesmo job — a atualização do
x86 — reprovou do mesmo jeito, noutro cenário ("sem o TPM, ou com outro, a
tentativa nao se confirma e volta; com o TPM de volta, a velha desfaz pelo
journal"): o processador 0 em `0x6c7e370`, fora de um `hlt`, com as
interrupções ligadas; os outros três em `0x6c650d1`, num `hlt`; o `swtpm`
vivo; o último sinal 22 segundos depois da partida. O commit da CI 438 é
anterior ao diagnóstico novo, e a linha dos módulos não saiu; os endereços
dizem o lugar: com o mesmo firmware e a mesma máquina, as imagens do DXE
ficam nos mesmos lugares — o processador 0 no laço do `Stall`
(`Metronome+0x370`), e os estacionados no `CpuDxe`; quem chamou o
`Stall`, só a pilha diria, e o retrato é o da CI 436. O boot parado era o
seguinte a um reinício, como na CI 413: o kernel tinha subido sobre o
outro TPM, recusado o journal e reiniciado a máquina para o slot que o
controle diz — o `ide0-hd0` já tinha lido 16,8 MB, o kernel, pelo
iniciador —, e o firmware parou no mesmo processo do emulador.

**A máquina.** Desde então, toda máquina que o `xtask` liga pelo firmware
— as bancadas, a suíte do x86, as fumaças, a sonda do iniciador, a máquina
com o disco no NVMe e a do disco hostil, os pares — diz ao firmware por
onde ela boota: o disco do boot leva `bootindex=0`, e só ele
(`argumentos_dos_discos`, em [`xtask/src/main.rs`](../xtask/src/main.rs)).
No x86 com o disco no virtio, é o IDE, sobre o mesmo arquivo — declarado
agora por `-drive if=none` e `-device ide-hd`, no primeiro canal, como
unidade mestre, onde o `-drive` sem `if=` o punha, e com o mesmo nome,
`ide0-hd0` —; no x86 com o disco no NVMe, o NVMe; no ARM, o `disco0`, no
virtio-blk ou no NVMe. Sem firmware — o ARM pelo `-kernel` —, nenhum. E a
linha que o `comando_qemu` monta é conferida inteira antes de o emulador
existir (`conferir_o_disco_do_boot`): numa máquina que sobe pelo firmware,
um dispositivo só leva a ordem, com o valor 0, e é o disco do boot; sem
firmware, nenhum. Uma ordem a mais — numa placa de rede, para o PXE — ou a
menos não impediria a máquina de subir: o firmware bootaria de outro lugar,
ou voltaria ao `ConnectAll`, calado. A recusa diz o que achou. O que a
suíte e a sonda do iniciador acrescentam à linha depois dela — o NVMe dos
casos e a placa Intel — não leva ordem
(`os_dispositivos_da_suite_nao_levam_ordem_de_boot`). Mudar a máquina de
todas as bancadas e da suíte foi tratado como [B] (`CLAUDE.md`, 1.6): é
configuração de teste, que não muda o Gate, a Policy nem o que o Duke
garante.

Com um `bootindex`, o QEMU entrega ao firmware o arquivo `bootorder` pelo
`fw_cfg`, e o BDS do OVMF (`PlatformBdsConnectSequence`) e o do AAVMF (no
2025.11 da CI, a `PlatformBootManagerLibLight` do `ArmVirtQemu`) chamam o
`ConnectDevicesFromQemu`: ligam só os caminhos da ordem, e os filhos deles
— medido nos dois firmwares de cada arquitetura, o da CI e o daqui,
abaixo. O `EfiBootManagerConnectAll` fica para quando a ordem falta, ou
quando nenhum caminho dela se traduz. O resto continua como era: as
pontes PCI, que dão endereço a todo dispositivo; os consoles — a COM1, a
COM2, a tela, o console virtio, o teclado —; e o gerador de números, que
os dois ligam sempre. A placa de rede fica sem driver do firmware, e a
pilha de rede não sobe — e no OVMF da CI, fora dela, só o `VirtioRngDxe`
e o `RngDxe`, que produzem o `EFI_RNG_PROTOCOL`, e o shell, que não roda,
citam o protocolo. O kernel recebe a placa como o emulador a criou — como
já a recebia no ARM pelo `-kernel`, sem firmware nenhum —, e, no x86, o
disco virtio sem o firmware ter lido nada dele. O iniciador acha o disco
de onde veio pelo caminho da própria imagem (`iniciador/src/slots.rs`),
que é o que o firmware ligou. E, no x86, o CD vazio que o QEMU acrescenta
à máquina `pc` (`ide1-cd0`) sai: ele só entra quando nenhum disco é
declarado por `-device ide-hd`.

**A prova.** No firmware sozinho, parando a máquina no `BdsDxe: loading`,
com um disco virtio a mais, sem ordem, que só o `ConnectAll` lê (a placa
"intocada" é a de estado zerado no `x-query-virtio-status`: nenhum driver
a iniciou), dois boots em cada linha, com os mesmos números nos dois:

| Firmware | Sem a ordem | Com a ordem |
|---|---|---|
| OVMF da CI (2025.11), o disco no virtio | a placa de rede com `DRIVER_OK`; o `disco0` com 79 leituras e o disco a mais com 10; a opção de boot aos 4,1–4,2 s | a placa intocada; o `disco0` e o disco a mais sem nenhuma leitura; a opção de boot aos 3,2–3,3 s |
| OVMF daqui (2024.02), o disco no virtio | o mesmo; 4,4–4,6 s | o mesmo; 3,5–3,7 s |
| OVMF da CI, o disco no NVMe | a placa com `DRIVER_OK`; o disco a mais com 10 leituras; 2,8 s | a placa intocada; o disco a mais sem leitura; 2,3–2,5 s |
| AAVMF da CI (2025.11), o `disco0` no virtio-blk e no NVMe | a placa com `DRIVER_OK`; o disco a mais com 10 leituras; 6,1–6,3 s | a placa intocada; o disco a mais sem leitura; 5,9–6,1 s |
| AAVMF daqui (2024.02), o `disco0` no virtio-blk | o mesmo; 6,0 s | o mesmo; 5,8 s |

E o estresse que pegou a parada da CI 436 — o firmware da CI até a opção
de boot, com a CPU disputada por quatro processos ocupados, os estímulos
da espera da bancada, um TPM novo e uma cópia nova das variáveis a cada
boot —, com a linha nova: 400 boots, nenhum parado, e em todos, parada a
máquina no `BdsDxe: loading`, a placa de rede intocada e o `disco0` sem
leitura; a opção de boot aos 7,0 segundos em média, de 5,3 a 8,7 — sem a
ordem, eram 8,4, até 10,6, e um parado em duzentos. A contagem sozinha não
provaria: com uma parada em duzentos, quatrocentos boots sem nenhuma
aconteceriam cerca de uma vez em sete. O que prova é a placa intocada em
todos: sem driver nela, a pilha de rede não sobe, e nada chama o gerador
de dentro de um temporizador.

E as rodadas inteiras, com a máquina nova, uma de cada vez, todas
passando: a sonda do iniciador do x86 — o relatório inteiro: o controle na
cópia 0, sequência 1, o slot A lido e conferido pelo protocolo de bloco do
disco do boot, o mapa e a tela; o kernel assumindo a máquina; os quatro
kernels estragados recusados —; a fumaça do teclado USB; a suíte do x86
inteira, 910 de 910; o par de duas máquinas do x86, cada uma com a ordem
no IDE do próprio disco; a bancada da atualização do x86 inteira, os
dezoito cenários, em duas rodadas — os doze primeiros e os seis de queda;
a da persistência do x86 em quatorze cenários, escolhidos pelo que mudam
no boot — o disco do sistema no NVMe; o disco hostil por trás dele, no
cache que se perde, no erro de mídia e no disco que para de responder; a
placa Intel como a única; o reinício e o desligamento pelo comando; a
máquina de 1 GiB; o TPM pela CRB, e sem TPM; a imagem de produção; os
dois boots sobre o mesmo TPM; a partição de estado; e a queda em cada
fronteira de uma operação —; e, no ARM, a sonda do iniciador com a suíte
inteira pelo AAVMF, 908 de 908, e a bancada da atualização em quatro
cenários — o primeiro boot pelo firmware, a versão nova tentada e
confirmada, o cenário da CI 438 (sem o TPM, ou com outro) e o disco que
falha no slot inativo, com o firmware bootando do NVMe sobre o disco
hostil. Nada no kernel mudou, nem no iniciador.

As mutações N221–N228 estão em [`SDK.md`](SDK.md).

## A cópia da auditoria para o journal: a trava do gate

A trava da auditoria é a do gate: todo pedido auditado a toma, com as
interrupções mascaradas, para anexar o registro dele ao anel. O coletor
— e toda gravação que leva a auditoria pendente — montava as entradas do
journal com ela na mão: para cada registro, a codificação, a entrada e o
campo do conteúdo — quatro ou cinco alocações, e outras tantas
devoluções —, mais o vetor do conteúdo crescendo e o dos pendentes,
juntado do anel inteiro. O alocador do kernel tem uma trava só, disputada
pelos núcleos — o executor aloca a cada pedido —, e percorre a lista
livre a cada chamada. Medido em 8/11/2026, na investigação de
`nativo::atender_pendentes`: um lote de 16 KiB segurava a trava de 20 a
64 ms em depuração, e o gate esperava por ela de 21 a 51 ms; em
`release`, sob carga, de 16,7 a 28,4 ms, com o gate esperando até
12,8 ms. O tique e os dispositivos do núcleo do coletor ficavam parados
o mesmo tempo.

### A cópia

Com a trava na mão, agora, só se **copia**
(`persistencia::auditoria_que_cabe`): a lacuna, se o anel perdeu
registros depois da gravada, e os registros seguintes que cabem no
registro do journal — cada um codificado
(`politica::auditoria::codificar_em`) para dentro de um lugar reservado
antes de a trava ser tomada, com a sequência e o elo dele. Nenhum pedido
ao alocador lá dentro. Com a trava solta, as entradas são montadas pelas
mesmas funções de sempre, e o registro é gravado como antes.

- **O formato não muda.** A codificação é uma só: `codificar` é
  `codificar_em` num vetor do tamanho certo, e as entradas são as de
  sempre. O tamanho que a cópia reserva (`tamanho_codificado`) é
  conferido contra a codificação no hospedeiro.
- **A fotografia.** A lacuna, os registros e os elos saem da mesma tomada
  da trava, e os registros são os seguidos à gravada — ou à lacuna. O que
  é anexado depois da cópia tem sequência maior que a do último copiado e
  vai na gravação seguinte; o que o anel descarta depois dela já está
  copiado, e vai assim mesmo; e, se ele descartar também o que vinha
  depois dos copiados, a gravação seguinte o diz numa lacuna, a partir do
  último gravado — como sempre disse.
- **Um escritor só.** Só quem tem a ordem das gravações copia e grava, e
  só ela anda a gravada, depois de o registro estar escrito e
  descarregado: entre a cópia e a gravação, ninguém copia a mesma faixa,
  e a gravada não anda. Na suíte, a cópia sem a ordem é um pânico.
- **A queda.** A gravada não vai ao disco: o boot a refaz do journal. Uma
  queda em qualquer ponto da coleta — com a cópia feita, no meio da
  escrita, depois da descarga e antes de a gravada andar — deixa o
  journal com o registro inteiro ou sem ele, e o boot continua a cadeia
  do último que está lá. Entre a cópia e a montagem nada vai ao disco: a
  queda ali é a de antes da escrita.
- **As duas contas.** A tomada decide o que cabe pelo tamanho que cada
  entrada vai ter (`ENVELOPE_DO_EVENTO` e o tamanho codificado, e
  `ENTRADA_DA_LACUNA`); a montagem, pelo tamanho que ela tem. Iguais, a
  montagem leva tudo o que se copiou e nada mais coube; divergindo, o
  journal sairia certo assim mesmo — a gravada segue o último montado —,
  só com registros copiados à toa com a trava do gate na mão, ou lotes
  menores, e nenhum caso o veria. Na suíte, toda gravação confere que a
  montagem ocupou exatamente o que a tomada contou
  (`coleta_de_teste::montada`), e a diferença é um pânico.
- **A compactação** copia o anel do mesmo jeito: a primeira tomada só
  mede quantos registros são e quantos pedaços de 16 KiB a cópia ocupa;
  os pedaços são reservados fora; a segunda copia. Entre as duas, o anel
  só perde registros desses, pela ponta — os que entram têm sequência
  maior que a gravada, e a gravada não anda, que a ordem das gravações é
  da compactação (na suíte, a compactação sem ela é um pânico) —, e a
  cópia cabe no que se mediu. A marca da base sai da tomada que copia: do
  primeiro copiado, e não do primeiro que a medida contou.
- **Os pedidos ao heap.** Na cópia do coletor, o pedaço é do tamanho do
  orçamento — até 16 KiB —, e as anotações dos copiados — a sequência, o
  elo e onde cada um acaba, 56 bytes por registro — são reservadas para
  231 registros, mais do que um lote de 16 KiB leva: uns 13 KiB. Na
  compactação, cada pedaço da cópia tem 16 KiB, mas as anotações são um
  pedido só, do tamanho do anel: até 56 KiB, com ele cheio de 1024. É
  menos que os 64 KiB que uma parte da base já pede ao montar, e perto dos
  48 KiB que o vetor das entradas da auditoria da base pedia antes, de uma
  vez, ao dobrar.

### O que continua com a trava

- O próprio anexar: o elo, um BLAKE2s, e, com o anel cheio, a devolução
  do registro que sai pela ponta — cinco devoluções ao alocador, com a
  trava na mão. É de cada pedido auditado, e não do coletor.
- O `audit.tail`, que copia até 128 registros para responder — até cinco
  alocações por registro, com a trava na mão —, e o `audit.verify`, que
  refaz os elos do anel inteiro com ela.

Nenhum dos três é a codificação pendente para o journal; ficam
registrados, para uma medida e uma decisão à parte.

### Os testes

| Onde | O que confere |
|---|---|
| hospedeiro (`politica`): *o tamanho codificado é o da codificação*, *codificar_em acrescenta o mesmo sem alocar*, *antes e depois pela posição são os do filtro* | a conta do tamanho igual à da codificação, com o corte do texto acima do teto; a codificação acrescentada igual byte a byte, sem trocar de memória com o lugar reservado; os guardados antes e depois de uma sequência, achados pela posição, iguais aos do filtro — e a lacuna, a de sempre, e nenhuma depois de `u64::MAX`, sem dar a volta |
| suíte: os casos `coleta:` | antes, o controle positivo das contas: um pedido ao alocador e uma montagem feitos de propósito com a trava na mão são contados; a cópia sem nenhum pedido ao alocador com a trava na mão — pela conta do próprio alocador — e nenhuma entrada montada com ela; cada registro copiado com a trava montado, e, em toda gravação da suíte, a montagem com o tamanho que a tomada contou; o auditado logo depois da cópia, no ponto exato, que vai na gravação seguinte; o anel que transborda no meio da coleta, com o copiado inteiro e a lacuna do resto; a gravação que falha, sem andar a gravada; produtores em vários núcleos e três coletores, sem perder, repetir ou desordenar, e o boot seguinte com a mesma cadeia; a compactação, com inteiro o que o anel tinha até a gravada na tomada da cópia, medido nela; e o anel que perde registros entre as duas tomadas da compactação, por um gancho da suíte — a base é a marca até o de antes do primeiro copiado e os copiados até a gravada, lida do disco, e o boot seguinte a adota |
| hospedeiro (`xtask`): *o anel do corte que confere*, *o visto antes do anel que não deu a volta* | os vistos de antes do começo do anel do boot novo só deixam de contar se ele deu a volta — tem o que o anel guarda, 1024; com um a menos, reprovam |
| bancada de persistência: *a queda no meio da coleta da auditoria sob carga* | a serial pedindo sem parar, e a energia cai em cada fronteira do décimo registro só de auditoria do boot; no boot seguinte, nada do que se viu gravado sumiu ou mudou — e nenhum ficou de fora do anel sem ele ter dado a volta —, o anel sem buraco nem repetição, a cadeia se verifica, e o registro do corte, se estava no disco, trouxe o que levava (uma conferência de sanidade: a exata é a do cenário *a queda em cada fronteira de um registro só de auditoria*); mais um boot confere de novo |
