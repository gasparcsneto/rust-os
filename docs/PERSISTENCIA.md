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

- **Os prazos são do tempo lógico** — o RTC com o piso do journal —, com
  a resolução do RTC, um segundo. Um prazo não volta a correr num boot com
  o RTC atrasado. O tempo desde o boot só diz ao coletor de quanto em
  quanto olhar.
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
- **O heap do kernel tem 4 MiB.** O anel da auditoria cheio é perto de
  meio MiB, e um registro de 64 KiB passa pelo heap algumas vezes; uma
  falha de alocação no kernel é pânico.
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
setores de reserva (o plano de queda da bancada mora ali). O journal vive
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
