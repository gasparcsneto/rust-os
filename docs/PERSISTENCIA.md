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
- **`system.info` diz a região**, quanto dela está usado, de quantos
  setores, e quantas compactações houve.
- **O plano de queda** ganhou o ponto *depois da primeira parte*, o
  tamanho das regiões (para encher uma com poucas dezenas de operações) e
  duas bandeiras: o coletor não compacta, o boot não compacta.

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
| 7.4 | Mensagens persistentes, e as fronteiras entre o disco e o TPM | feita |
| 7.5 | Auditoria persistente | feita |
| 7.6 | Compactação e disco cheio | feita |
| 7.7 | O que restar da âncora (TPM físico, sessão autenticada no barramento) | — |
