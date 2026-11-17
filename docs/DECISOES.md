# As decisões abertas

Este é o dossiê das decisões [C] que o roteiro do Duke espera: as que
pedem a aprovação explícita do dono do projeto antes da primeira linha
(`CLAUDE.md`, [1.6](../CLAUDE.md#16-as-decisões-a-b-c) e
[5.3](../CLAUDE.md#53-as-decisões-c)). Elas estão espalhadas pelo README e
por `docs/`; aqui ficam juntas, cada uma com os dados para decidir, para
que o dono decida de uma vez e o desenvolvimento siga.

**Nada aqui está decidido.** Recomendar não é aprovar (1.6): cada entrada
diz o que este dossiê recomenda, e nenhuma muda de estado sem a palavra do
dono. Nenhuma se implementa antes da aprovação (5.3). E nenhuma trava o
resto: o trabalho que não depende de uma decisão continua
([5.4](../CLAUDE.md#54-o-trabalho-que-não-espera)) — cada proposta diz o
que não espera.

**Como ler.**

- [O índice](#o-índice) tem uma linha por decisão aberta: o id, a decisão,
  a área de 5.3 que a faz [C], o que ela destrava no roteiro, a exposição
  de hoje — o risco real enquanto ela espera, se há — e a fonte.
- [A ordem recomendada](#a-ordem-recomendada) diz por onde começar, e por
  quê.
- [As propostas completas](#as-propostas-completas) — as cinco primeiras
  da ordem — seguem o formato de 5.3: o problema, as evidências, as
  alternativas, os riscos, o impacto, a recomendação e o plano de
  validação; e mais o que não espera e as fechadas que cada uma toca.
  [As outras](#as-outras) têm uma entrada curta: o problema, as
  alternativas, a recomendação provisória e o que destrava.
- [As fechadas](#as-fechadas-que-não-se-reabrem) são o que não se propõe
  de novo.
- Os ids do projeto ficam (DT-1, B5-1, A1-4); os novos dizem a fase do
  roteiro (`R12-`, `R13-`, `R15-`) ou o assunto. Uma alternativa que não
  sai das fontes, nem decorre direto das invariantes, leva **(minha)**: é
  deste dossiê, e vale como sugestão, não como desenho.
- As fontes são as do commit `7141f66`, de 17/11/2026. Se uma fonte mudar,
  ela vale. Quando o dono decidir, a entrada passa às fechadas, com a data
  e a alternativa, e o README — as [Decisões
  pendentes](../README.md#decisões-pendentes) e o
  [Roteiro](../README.md#roteiro) — se acerta.

## O índice

Na ordem recomendada.

| Id | Decisão | Área de 5.3 | Destrava | Exposição de hoje | Fonte |
|---|---|---|---|---|---|
| [DT-1](#dt-1) | O Terminal, o servidor de janelas e o teclado da Pessoa | identidade e confiança; chamadas fora do gate | o consentimento (fase 13); os resíduos do passo 1, do ξ e do ο | **real**: outro principal toma o foco, ou o nome `terminal` ou `janelas`, e recebe o que a Pessoa digita — a senha também —, sem registro | [README](../README.md#decisões-pendentes) |
| [COTA-SOMA](#cota-soma) | A soma das cotas de processos e a cota por sessão | semântica de operação (a cota e a alocação) | a operação sob carga (fase 14); mais sessões e dispositivos (fase 15) | **real**, pela leitura: várias sessões da mesma chave, ou vários titulares, enchem a tabela de fios, e nada nasce — nem o Terminal, nem o `energia` do `system.reboot` | [README](../README.md#decisões-pendentes) |
| [R13-BOOT](#r13-boot) | A cadeia de boot confiável | identidade e confiança; custódia (a política dos selos) | a fase 13; o Secure Boot que a fase 14 deixou de fora; a base de R12-IC-TPM e R12-IC-VALOR | **real, com a máquina na mão**: o disco e o TPM juntos abrem os selos da identidade e das chaves; o firmware não confere o iniciador | [Roteiro](../README.md#roteiro), fase 13 |
| [R13-CONSENT](#r13-consent) | O consentimento — a Pessoa perguntada, e o registro que ela lê | Policy e autorização; quem lê a auditoria | o título da fase 13 | baixa: um agente edita o campo que a Pessoa largou, sem perguntar; ela não lê o registro | [Roteiro](../README.md#roteiro), fase 13 |
| [ALC-TEMP](#alc-temp) | A expansão temporária de alcance, por titular | Policy; autoridade dada por tempo | parte do consentimento | indireta: o acesso de uma hora vira linha da política até alguém tirá-la | [USABILIDADE](USABILIDADE.md#decisões-novas--para-quem-decide) |
| [M-EXEC](#m-exec) | O `exec` e a malha do processo | identidade de programa e proveniência | um limite do SDK; o handoff e a continuidade (fase 15) | baixa: num endpoint, a descoberta e a auditoria mostram o programa que não roda mais | [README](../README.md#decisões-pendentes) |
| [A9-RESUMO](#a9-resumo) | O tamanho do resumo na descrição de um programa | auditoria e proveniência | — | baixa: com a chave de um editor e uns 2^32 resumos, dois executáveis com a mesma descrição | [README](../README.md#decisões-pendentes) |
| [A1-4](#a1-4) | O que a recusa da cota mostra | o texto da auditoria — talvez [B] | — | nenhuma: diagnóstico | [README](../README.md#decisões-pendentes) |
| [SDK-CANAL](#sdk-canal) | O canal sem nome | o contrato v2 (DS-2) — talvez [B] | um limite do SDK | baixa: quem toma os nomes do laço de um processo o impede de esperar | [SDK](SDK.md#limites-conhecidos) |
| [AUD-ANEL](#aud-anel) | Os registros do boot que saem do anel antes do journal | auditoria (uma lacuna nova) | — | baixa: hoje o boot faz poucos registros antes do journal | [PERSISTENCIA](PERSISTENCIA.md#a-reconstrução-da-auditoria-no-boot-b4) |
| [P-HISTORIA](#p-historia) | A história da autoridade que cresce sem fim | persistência (o formato da base) | — | baixa: depois de dezenas de milhares de operações, a persistência para, fechada | [PERSISTENCIA](PERSISTENCIA.md#como-ficou-76) |
| [R13-DESFAZER](#r13-desfazer) | O desfazer | persistência e auditoria | fecha a fase 13 | nenhuma nova | [Roteiro](../README.md#roteiro), fase 13 |
| [R12-SIMD](#r12-simd) | O SIMD nos processos | semântica de operação (o contrato dos registradores) | as otimizações de cifra (fase 12) | nenhuma: o custo da cifra em software | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-mTLS](#r12-mtls) | O certificado do cliente no TLS | criptografia e custódia (um domínio de assinatura novo) | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-PROXY](#r12-proxy) | O *proxy* | o Gate (um destino que ele não vê) | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-QUIC](#r12-quic) | O HTTP/3 e o QUIC | depois da avaliação, que é [B] | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-IC-TPM](#r12-ic-tpm) | A chave de assinatura dentro do TPM | custódia | a fase 12 (Web3) | a privada vive na memória do kernel; só a semente está selada | [ICP](ICP.md#o-que-não-existe-ainda) |
| [R12-IC-VALOR](#r12-ic-valor) | A rede principal com valor e com canister | custódia; operação irreversível (5.6) | a fase 12 (Web3) | nenhuma: a política padrão não alcança a rede principal | [ICP](ICP.md#na-rede-principal) |
| [R12-IC-NOS](#r12-ic-nos) | Os nós da rede principal pela árvore de estado | Policy (de onde vem um destino) | a fumaça real que fecha sempre | disponibilidade: os nós giram, e a fumaça falha fechada | [ICP](ICP.md#o-que-fica-de-fora) |
| [R12-IC-OUTROS](#r12-ic-outros) | O resto do IC | conforme o item | — | nenhuma | [ICP](ICP.md#o-que-não-existe-ainda) |
| [R15-HANDOFF](#r15-handoff) | O handoff | identidade e autoridade entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-REMOTOS](#r15-remotos) | Os recursos remotos | identidade e autoridade entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-PRESENCA](#r15-presenca) | A presença | identidade e confiança entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-CONTINUIDADE](#r15-continuidade) | A continuidade | semântica de operação entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-PACOTES](#r15-pacotes) | Os pacotes | confiança (editores, versões, revogação de selo) | a fase 15 | nenhuma | [SDK](SDK.md#o-que-não-existe) |
| [B5-1](#b5-1) | Restaurar num volume recusado | persistência (a âncora) | o grupo B da fase 14 | operação: o volume recusado não volta | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-2](#b5-2) | Recuperar depois de perder o disco | custódia e confiança | o grupo B da fase 14 | operação: as cópias de um disco perdido não abrem | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-3](#b5-3) | Restaurar noutra máquina, ou migrar | identidade e confiança entre máquinas | o grupo B da fase 14 | operação: uma cópia não sai da máquina | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-4](#b5-4) | Restaurar o estado de autoridade | persistência (R1, R6) | o grupo B da fase 14 | operação: o estado de autoridade não está na cópia | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |

## A ordem recomendada

Dois critérios, nesta ordem: reduzir primeiro uma exposição real, e
depois destravar o que mais trava o roteiro. E uma regra: o que depende de
outra decisão vem depois dela.

1. **DT-1** — a maior exposição que espera uma decisão: a credencial da
   Pessoa capturada por outro principal, sem registro. E é a base do
   consentimento: nada se pergunta à Pessoa por um caminho que outro
   processo imita.
2. **COTA-SOMA** — a outra exposição real: um principal com várias
   sessões, ou alguns titulares juntos, param a criação de fios da
   máquina. A decisão é estreita, e as correções [B] em volta não esperam.
3. **R13-BOOT** — fecha a exposição de quem tem a máquina na mão; é o
   incremento seguinte da fase 13; traz o Secure Boot que a fase 14 deixou
   de fora; e é a base de custódia que R12-IC-TPM e R12-IC-VALOR pedem.
4. **R13-CONSENT**, com a **ALC-TEMP** — o título da fase 13. Depende da
   DT-1: perguntar à Pessoa pede o caminho dela. A expansão temporária de
   alcance é a forma mais direta do consentimento — "esta pessoa deixa
   este agente, neste recurso, por uma hora" —, e se decide junto.
5. **M-EXEC** — pequena e com precedente: a ponta de um fluxo já não
   sobrevive ao `exec`. Tira um limite do SDK e fixa o ciclo de vida do
   endpoint antes do handoff e da continuidade.
6. **O lote rápido** — A9-RESUMO, A1-4, SDK-CANAL, AUD-ANEL e P-HISTORIA:
   exposição baixa, alternativas curtas, decididas de uma vez. Duas delas
   (A1-4 e SDK-CANAL) talvez nem sejam [C] pela 5.3 de 17/11/2026: o dono
   pode devolvê-las ao [B].
7. **R13-DESFAZER** — fecha a fase 13; depende do R13-CONSENT.
8. **R12-SIMD, R12-mTLS e R12-PROXY** — fecham os incrementos de
   infraestrutura da fase 12. **R12-QUIC** depois da avaliação, que é [B]
   e começa já.
9. **R12-IC-TPM e R12-IC-VALOR**, depois da R13-BOOT; **R12-IC-NOS** e
   **R12-IC-OUTROS** quando houver a necessidade.
10. **Os marcos da fase 15**, na ordem do roteiro — R15-HANDOFF,
    R15-REMOTOS, R15-PRESENCA, R15-CONTINUIDADE e R15-PACOTES —, o handoff
    e a continuidade depois da M-EXEC. Cada um pede antes um desenho com as
    decisões dele, como o DN-1, o DN-2 e o DN-3 pediram.
11. **B5-1 a B5-4** — o B5-1 é o único que não esbarra numa fechada; os
    outros três esbarram no B2, na invariante da identidade, ou na R1 e na
    R6.

## As propostas completas

### DT-1

**O Terminal, o servidor de janelas e o teclado da Pessoa.** Inclui o A3
("o ritmo da senha nos contadores") e o A5 ("o registro por tecla com o
foco tomado") da pendência antiga do coordenador, e o A4 (a senha no lugar
errado). Os rótulos DT-1a a DT-1e são os das mensagens de commit; o README
usa só "DT-1a".

**O problema.** O caminho da tecla da Pessoa até o console não tem, para o
kernel, um dono definido. O README pergunta três coisas que nenhuma regra
responde hoje: "quem pode ser 'o Terminal' e 'o servidor' para o kernel,
quem move o teclado da Pessoa, por onde uma credencial entra".

- **Quem é o Terminal e o servidor.** A barra entrega o `ABRIR` a quem
  escuta os nomes `terminal` e `janelas`, e `escutar` não reserva nome
  nenhum nem passa pelo gate. Um processo de outro principal que tome o
  `terminal` com o Terminal fechado, ou o `janelas` com o servidor fora do
  ar — e a barra publica nele o "Sobre" e o Terminal —, recebe o pedido, e
  pode desenhar uma janela que se passa pelo Terminal. Prender-se ao
  pseudo-terminal já é decidido — `terminal.attach`, que só o `sistema`
  enumera —; mas, dentro disso, quem escreve no pseudo-terminal sem a
  marca da árvore digita como a Pessoa (DT-1a), e escolhe a linha que o
  Enter pedido por um agente confirma (o O6 do adversário ο).
- **Quem move o teclado.** Qualquer processo dono de uma superfície, até
  invisível, pede o foco do teclado quando quer (`controlar` com `FOCO`,
  sem gate), e a janela com o foco recebe as teclas — a senha também
  (DT-1b; o N2a; o A5: a linha por tecla saiu do log do servidor, no N2, e
  o foco tomado ficou). E o `press` de um agente na caixa de fechar do
  Terminal fecha o console e encerra a sessão da Pessoa que está nele —
  gravado, e não recusado (DT-1e; o X2 do adversário ξ).
- **Por onde a credencial entra, e o que ela deixa.** A senha digitada
  adiantado num Terminal entra no histórico do teclado, que só o `sistema`
  lê (DT-1c; o X3 do ξ); a digitada no lugar errado — numa linha que pede
  um comando — ecoa, vai à árvore e ao histórico (o A4); a versão e o
  prazo do campo, e o `revision` da árvore, crescem a cada tecla, também
  da senha (DT-1c; o resto do N3); e os contadores do `system.read` — o
  `scheduled` dos fios do Terminal e do servidor, a linha do teclado em
  `irq.stats`, os despertares, as trocas de contexto e as chamadas de
  sistema — andam tecla a tecla, e o `observador` os lê (o A3). O
  `ui.claim` de um agente arrenda a linha do nome, da senha ou da
  cerimônia por até 300 s, renováveis, e as teclas da Pessoa nela são
  `CONFLICT` (DT-1d); a tecla dela entre a entrada de uma edição da árvore
  e o consumo do Enter também (o resto do achado 2 do adversário do passo
  1).

**A exposição de hoje.** Real. Um processo de outro principal — um
programa que um agente lançou, por exemplo — cria uma superfície, toma o
foco e recebe as teclas da Pessoa — a senha também, com uma Pessoa entrada
no console físico —, e a captura não deixa registro: `superficie`,
`controlar` e `escutar` não passam pelo gate. A senha capturada não abre
nada pelo canal do agente, pela malha nem pelo enlace — o login só existe
no teclado de um console —, mas serve a quem tem um teclado nesta máquina,
e onde mais a Pessoa a repetir. Um agente segura as linhas da Pessoa por
arrendamentos renováveis, e encerra a sessão dela num Terminal; os dois
ficam gravados.

**O que já entrou como [B]** — o passo 1 da continuidade e os achados do ξ
e do ο, sem esperar a decisão: a senha fora da auditoria, do log e dos
relatórios; o servidor de janelas sem a tecla no log (o N2); o
`display.info` sem o `typed` (o N3, em parte); a tecla do console físico
no histórico só quando ele a consome; as cópias da tecla zeradas; o resto
da senha engolido quando a cerimônia acaba no meio dela; o agente que não
edita nem confirma as linhas da Pessoa, também num Terminal, conferido na
entrada e de novo no consumo; o valor de um `set_value` só com o que se
digita; e o Enter de agente só quando pedido, amarrado à conexão.

**As evidências.**

- As fontes: [README, Decisões pendentes](../README.md#decisões-pendentes)
  (a DT-1); [Consoles](../README.md#consoles); [Coordenação](../README.md#coordenação)
  — "Foco ≠ autoridade ≠ arrendamento" e "nenhuma prioridade de um sobre o
  outro"; [Operar por uma pessoa](../README.md#operar-por-uma-pessoa) — "O
  teclado tem dono"; [OPERACAO, A própria senha](OPERACAO.md#a-própria-senha).
- O código: `kernel/src/eventos.rs` — o `escutar`, "que não passa pelo
  gate"; `kernel/src/superficies.rs` — o `controlar` com `FOCO`, que só
  confere o dono da superfície; `kernel/src/usuario/mod.rs` — o `terminal`
  decide `terminal.attach`, e o `escutar`, o `superficie` e o `controlar`
  não passam pelo gate; `kernel/src/barra.rs` — `pressionar_terminal`
  publica no canal `terminal`, ou no `janelas`.
- Os casos da suíte que já cercam o caminho: `terminal: o agente nao edita
  nem confirma a linha da senha`, `consoles: a senha digitada adiantado nao
  entra no historico`, `terminal: a edicao da arvore que corre com o Enter
  da pessoa nao entra na linha do nome`, `terminal: a tecla da pessoa
  depois do Enter, com a edicao a caminho, nao e CONFLICT`, `terminal: o
  logout diz quem fechou` e `terminal: o Enter de agente que a arvore nao
  pediu e descartado`. E `janelas: sobre o duke pela barra`, que digita uma
  senha inteira com o "Sobre" na frente: as teclas vão ao servidor, que já
  não as grava — é o caminho da captura pelo foco, com um processo do
  próprio sistema.
- As mutações dos consoles e do Terminal: N88 a N105, N126 a N156, N162 a
  N172, e as do AE-5 sobre os consoles, N189 a N208 menos a N196 (no
  README e em [SDK, Mutações](SDK.md#mutações)).
- Da pendência antiga — "o ritmo da senha nos contadores (A3), o registro
  por tecla com o foco tomado (A5), F4, F6" —, o A3 e o A5 estão acima. O
  F4 e o F6 não aparecem no README, em `docs/`, no código nem nas
  mensagens de commit: do adversário do AE-1, há registro do F1, do F2,
  do F3 e do F5.

**As alternativas**, por pergunta:

1. **O Terminal e o servidor.**
   - (a) **(minha)** Os nomes `terminal` e `janelas` reservados ao
     Terminal e ao servidor de janelas, reconhecidos pela identidade de
     programa que o kernel carregou — o nome do manifesto, o resumo da
     imagem, sem editor de fora ([MALHA, A identidade de um
     programa](MALHA.md#a-identidade-de-um-programa)) — e pelo titular
     `sistema`. O `escutar` de outro nesses nomes é recusado, e gravado;
     quem escreve no pseudo-terminal sem a marca passa a ser só o Terminal
     reconhecido.
   - (b) **(minha)** Uma permissão nova do vocabulário fechado para
     escutar um nome do sistema, decidida pelo gate — como o
     `terminal.attach` já é para o pseudo-terminal.
   - (c) **(minha)** Como hoje, com a captura gravada: o `escutar` num
     nome do sistema e o foco tomado vão à auditoria. Só detecção.
2. **O foco.**
   - (a) **(minha, pelo uso de hoje)** O foco muda só pelo clique da
     Pessoa e para a superfície que acaba de abrir, uma vez — os dois usos
     que existem: "o kernel passou a dar o foco no aperto do botão", e "o
     servidor agora só pede o foco para a janela que acabou de abrir".
   - (b) **(minha)** O foco não sai de um console enquanto a linha dele
     pede uma credencial — o nome, as senhas, a cerimônia.
   - (c) O servidor reconhecido decide o foco de todas as janelas — o
     desenho do servidor no README, "o servidor decide janelas, decoração,
     foco e roteamento" —; o pedido de outro dono vira pedido a ele.
   - (d) **(minha)** Uma sequência de atenção segura: uma tecla que só o
     kernel trata e que leva a Pessoa ao console de verdade — a prática do
     Ctrl+Alt+Del.
3. **As linhas da Pessoa, e o que a tecla deixa.**
   - (a) As linhas de credencial são da Pessoa: o `ui.claim` de um agente
     nelas, e o `press` dele na caixa de fechar de um Terminal com alguém
     entrado, recusados; e a tecla de um Terminal coordenada — e escrita no
     histórico — onde o console a consome, como a do físico — o README:
     "desenho da mesma família".
     Muda a regra "nenhuma prioridade de um sobre o outro", só nessas
     linhas.
   - (b) Como hoje: o arrendamento do agente vale contra a Pessoa, o
     `press` fica gravado, e a coordenação fica na janela.
   - (c) Os contadores sem o grão da tecla — os dos fios do Terminal e do
     servidor e a linha do teclado somados por janela de tempo —, ou só
     para quem tem `audit.read`. O README: "muda o que esses relatórios
     prometem, ou a quem".
   - (d) **(minha)** Numa linha de credencial, a versão e o prazo do campo
     e o `revision` da árvore só andam no Enter.

**Os riscos.**

- 1(a) prende o Terminal e o servidor à imagem: um Terminal selado por um
  editor de fora não pode ser "o Terminal". E o servidor que cai precisa de
  quem o lance de novo: hoje, sem ele, a barra publica no nome livre.
- 1(b) cresce o vocabulário fechado da política e põe no gate uma chamada
  que hoje é só mecanismo — rara, e barata —, com uma permissão a mais em
  todo papel que serve janelas.
- 1(c) não fecha nada: a senha continua capturada, agora com registro.
- 2(a) muda o caminho do foco de uma janela que não acaba de abrir; um
  programa que hoje o pede a qualquer hora deixa de recebê-lo.
- 2(b) é uma regra nova no roteamento da tecla; sem a 1(a), uma janela
  falsa aberta antes da linha da senha ainda engana a Pessoa.
- 2(c) põe um protocolo novo entre cada programa e o servidor: o foco de
  uma superfície que não é dele.
- 2(d) é uma tecla que os três caminhos de hardware — o PS/2, o
  `virtio-input` e o USB — precisam entregar ao kernel, e uma tela que o
  kernel desenha.
- 3(a) muda a coordenação: a Pessoa passa a ter prioridade sobre o agente
  nas linhas de credencial. No resto, a regra fica.
- 3(c) muda o que o `observador` lê: os casos e as bancadas que contam o
  `scheduled` e o `irq.stats` mudam junto.

**O impacto.** O kernel: `eventos.rs` (os nomes), `superficies.rs` (o
foco), `barra.rs`, `teclado.rs` (o histórico), `interpretador.rs` e
`coordenacao.rs` (as linhas e o arrendamento), `ui.rs`, e os relatórios em
`agent/commands.rs`; os programas `terminal` e `janelas`; a política, só
na 1(b); o `cargo xtask invariantes`, os nomes reservados; e a
documentação dos [Consoles](../README.md#consoles), da
[Coordenação](../README.md#coordenação), de [Operar por uma
pessoa](../README.md#operar-por-uma-pessoa), do
[OPERACAO](OPERACAO.md#a-própria-senha) e do
[PAREAMENTO](PAREAMENTO.md#os-comandos). Uma recusa nova do `escutar` num
nome reservado é comportamento, e não um nome do contrato v2: conferir
contra a regra do DS-2 ([SDK, O contrato v2](SDK.md#o-contrato-v2-ds-2)).

**A recomendação.** Aprovar um princípio — **o caminho da Pessoa** —, de
que os itens da DT-1 saem como [B]:

1. o kernel conhece o Terminal e o servidor de janelas pelo programa que
   roda: os nomes `terminal` e `janelas` são deles (1a);
2. o foco muda pelo clique da Pessoa e para a janela que acaba de abrir, e
   não sai de uma linha que pede credencial (2a e 2b);
3. as linhas de credencial são da Pessoa: o `ui.claim` e o `press` de um
   agente nelas — e na caixa de fechar de um Terminal com alguém entrado —
   são recusados e gravados, e a tecla do Terminal é coordenada, e entra
   no histórico, onde o console a consome (3a);
4. a tecla de uma credencial não deixa rastro fora do console — nem na
   versão e no prazo do campo, nem no `revision` da árvore (3d) —, e os
   contadores do `system.read` deixam de andar tecla a tecla: somados por
   janela de tempo (3c).

A 2(d) fica para quando o caminho da Pessoa precisar dela. Fica, como
resíduo aceito, a senha digitada no lugar errado (o A4): numa linha de
comando, nada distingue uma senha de um comando.

**O plano de validação.**

- Um caso por caminho de captura — antes, para medir a exposição; depois,
  com a decisão: o processo de um agente que escuta `terminal` com o
  Terminal fechado; o que escuta `janelas` com o servidor fora; o dono de
  uma superfície invisível que pede o foco no meio da senha do login, da
  `senha` e da cerimônia; a senha adiantada num Terminal; o `ui.claim` de
  um agente na linha do nome; o `press` dele na caixa de fechar com a
  Pessoa entrada; os contadores que o `observador` lê, com uma senha
  digitada.
- As bancadas com a pessoa no teclado — `cargo xtask senha` e a do
  pareamento —, nas duas arquiteturas, em depuração e em release.
- Uma mutação por regra, uma de cada vez e restaurada: o nome reservado
  aceito; o foco dado no meio da credencial; o histórico escrito na
  chegada; o `ui.claim` aceito; o `press` aceito; o contador por tecla.
- Um agente adversário com uma tarefa só: capturar a senha da Pessoa por
  qualquer caminho ([1.5](../CLAUDE.md#15-segurança-o-agente-adversário)).
- A CI completa, verde no último commit.

**O que não espera.** Os casos que reproduzem cada caminho de captura, sem
mudar o comportamento: são os dados da decisão.

**As fechadas que ela toca.** O B3: um evento de hardware não é
autoridade — a tecla é evento; quem age é a sessão. O B4: a troca da
própria senha é do console. Nada aqui muda o gate, a política ou quem
decide: o caminho da Pessoa diz para onde a tecla vai, e não o que ela
autoriza.

### COTA-SOMA

**A soma das cotas de processos e a cota por sessão** — o que a decisão
14.1 não fecha.

**O problema.** A tabela de fios é uma só, para os fios do kernel e os
processos de todos: 95 vagas (`MAX_FIOS`), 89 livres na suíte com 4
núcleos. A cota de processos protege um titular dos outros — desde a 14.1
e a alternativa 1 do A1, os vivos, os que nascem, os zumbis e os mortos
ainda não recolhidos de um titular ocupam no máximo a cota dele —, mas não
protege a tabela:

- vários titulares, cada um dentro da cota, a enchem: doze de cota 8
  ocupam as 89 vagas, e numa máquina em uso, com os serviços e os
  programas do boot no ar, bastam menos;
- a cota é por sessão, e não por identidade: a mesma chave de agente nas 8
  sessões cifradas — as quatro portas do `virtio-console` e as quatro
  vagas do TCP — soma 8 cotas; e uma pessoa ganha uma cota nova a cada
  login, com os processos do login anterior ainda vivos.

Com a tabela cheia, não nasce fio nenhum, de ninguém: outro titular não
lança programa, o Terminal não abre, a cerimônia de pareamento não começa,
e o `system.reboot` não cria o fio `energia` — e falha depois de o pedido
ir ao journal.

**A exposição de hoje.** Real, pela leitura, sem reprodução:
disponibilidade. Um agente com a chave em várias sessões, ou alguns
titulares juntos, param a criação de fios da máquina. Volta pelo
`process.terminate` — do `sistema`, ou do administrador com a prova —, ou
pelo corte de energia.

**As evidências.** [README, Decisões
pendentes](../README.md#decisões-pendentes) — o item e os dois antes dele;
[Coordenação](../README.md#coordenação) — "A cota de processos", "O zumbi
na cota" e "Os mortos na cota"; a medida da 14.1: com a cota em 2, o
`colhedor` e 88 zumbis tomaram as 89 vagas livres, e daí em diante não
nascia fio nenhum, nem o `energia`; os casos `zumbis: o morto conta na cota
ate o recolhimento`, `zumbis: os fios do kernel nao contam na cota` e
`zumbis: a recusa grava os mortos acima da cota`; e [as mutações MC1 a
MC9](../README.md#as-mutações-da-conta-de-vagas-alternativa-1).

**As alternativas.** As três primeiras são as do README, e "a soma das
cotas de titulares diferentes nenhuma das três fecha sozinha":

- (a) contar a cota pela identidade — a chave do agente, a pessoa —, e não
  pela sessão: fecha a soma das sessões da mesma chave e a dos logins da
  mesma pessoa;
- (b) encerrar os processos com a sessão: fecha a dos logins. Os processos
  de uma sessão que acabou já não pedem nada — "os programas da pessoa que
  saiu não pedem mais nada" ([MALHA](MALHA.md#revogação-e-fim)) —, e hoje
  só ocupam a vaga;
- (c) reservar vagas aos fios do kernel — a alternativa (2) da decisão do
  A1, que segue aberta aqui: salva o `energia`, a cerimônia e o coletor, e
  não o programa de outro titular nem o Terminal, que é um processo;
- (d) **(minha)** uma reserva também para o titular `sistema` — o servidor
  de janelas e o Terminal —, além da dos fios do kernel;
- (e) aceitar, como está.

**Os riscos.**

- (a): quem usa várias sessões da mesma chave em paralelo passa a dividir
  uma cota; a pessoa no console físico e num Terminal também. A conta
  continua sob a trava do escalonador, no lugar da de hoje
  (`Escalonador::processos_de`).
- (b): muda o ciclo de vida do processo — o programa que a pessoa lançou
  morre no `logout`.
- (c) e (d): menos vagas para os processos; o tamanho da reserva é uma
  escolha a medir.
- Nenhuma fecha a soma de titulares diferentes. Com (a) e (c), o resíduo é
  o de muitos titulares registrados, cada um dentro da cota — e o registro
  de cada um é uma operação administrativa com prova.

**O impacto.** `kernel/src/fios` (a conta e a reserva); o sentido da linha
`processos <papel> <n>` da política, sem mudar a gramática; a
documentação da Coordenação e das Decisões pendentes; os casos `zumbis:` e
`recolhimento:`; uma campanha de mutações.

**A recomendação.** (a) + (c). A (b), só se a medida, depois delas, mostrar
processos de sessões acabadas segurando a cota de quem entra de novo; a
(d), se mostrar o Terminal sem vaga com (a) e (c).

**O plano de validação.** Primeiro, um caso que reproduz o esgotamento de
hoje — a mesma chave em várias sessões, e vários titulares —, para medir.
Depois, o mesmo caso com a decisão: a reserva intacta, o `system.reboot`,
o Terminal e a cerimônia de pé. As rajadas de `fork` de várias sessões ao
mesmo tempo, nas duas arquiteturas. As mutações, uma de cada vez: a conta
por sessão de volta, a reserva ignorada, a reserva contada na cota. A CI
completa.

**O que não espera** — as correções [B] que o README já separou, com a
numeração dele, cada uma com os seus testes:

- a (1): o fio `energia` criado no boot, parado, como o do botão;
- a (3): a contenção conferida de novo no nascimento, antes de o filho
  rodar — um `process.isolate` no meio deixa nascer um filho livre;
- a (4): o `process.terminate` de um processo que ainda nasce leva a marca
  ao fio definitivo, sob a mesma trava, e a desconta quando a vaga volta
  por falta de pilha;
- a (5): a recusa da cota num `fork` grava o processo que bifurcou;
- e a mitigação (3) da decisão do A1 — o nascimento que não acha vaga,
  havendo morto por recolher, acorda o coletor —, que não exclui a
  alternativa adotada.

**As fechadas que ela toca.** A 14.1 (alternativa A, 7/11/2026) e a
alternativa 1 do A1 (8/11/2026): a cota conta os zumbis e os mortos até o
recolhimento, e quem recolhe é só o coletor — a alternativa (4) do A1 foi
investigada e não adotada: traria de volta, pelo `fork`, o defeito do
AE-1.

### R13-BOOT

**A cadeia de boot confiável** — o incremento seguinte da fase 13.

**O problema.** O Duke não prova o código que boota. O firmware não
confere o iniciador: o Secure Boot fica desligado, e o iniciador não é
assinado. O iniciador confere resumos, e não assinaturas. Os selos do TPM
não estão presos à medição do boot: o da identidade do Duke (B2) "não tem
senha nem política", e o das chaves de assinatura (ICP-5) se prende ao
índice de geração — "o cofre não mede o boot: nenhum PCR entra na
política". A EK é confiança na primeira vez. E o código da imagem roda por
ser da imagem: "quem prova a imagem é a cadeia de boot confiável".

**A exposição de hoje.** Real, com a máquina na mão. Quem tem o disco
**e** a máquina — outro sistema bootado nela, ou alguém no barramento do
TPM mandando os próprios comandos — abre o selo da identidade; e quem tem
o disco e o mesmo TPM satisfaz a política das chaves vivas. O disco
sozinho não leva nada: o selo só abre no TPM em que nasceu. Sem acesso
físico, não há exposição.

**As evidências.** [OPERACAO, A identidade do
Duke](OPERACAO.md#a-identidade-do-duke) — "O que o selo protege, e o que
não" —, e a máquina de referência, com o Secure Boot desligado
([OPERACAO](OPERACAO.md#a-máquina-de-referência));
[ATUALIZACAO, O que fica de fora](ATUALIZACAO.md#o-que-fica-de-fora) — sem
Secure Boot; o iniciador não se atualiza —, e [Quem confia em
quê](ATUALIZACAO.md#quem-confia-em-quê); [PERSISTENCIA, Como ficou
(7.7)](PERSISTENCIA.md#como-ficou-77) — a EK como confiança na primeira
vez, e "os PCRs não entram" — e [Os riscos que
ficam](PERSISTENCIA.md#os-riscos-que-ficam) do cofre; [ICP, O que não
existe ainda](ICP.md#o-que-não-existe-ainda) — "o boot medido, com os PCRs
na política do selado"; o README, [O código de fora da
imagem](../README.md#o-código-de-fora-da-imagem) — "a imagem conferida".

**As alternativas.**

- (a) **O Secure Boot**: o firmware confere o iniciador, assinado por uma
  chave do projeto inscrita no firmware de cada máquina — uma raiz de
  confiança nova —; e **(minha)** o iniciador passa a conferir a
  assinatura do manifesto do slot, e não só os resumos que o controle
  guarda.
- (b) **O boot medido**: o iniciador mede o kernel do slot no TPM, e os
  selos — o da identidade e os das chaves — passam a exigir a medição. Do
  jeito simples, "quebraria a atualização A/B" (OPERACAO): a versão nova
  mede outro valor. Duas formas de não quebrar:
  - (b1) **(minha)** a versão que roda, medida e conferida, sela de novo
    para a medição da versão armada, dentro da instalação pelo quórum
    `system.update` — a confiança continua a do B1;
  - (b2) **(minha)** uma política autorizada por uma chave (o
    `TPM2_PolicyAuthorize`), que assina a medição de cada versão — o poder
    de abrir os selos passa a quem assina, sem o quórum.
- (c) **A EK conferida** contra a cadeia do fabricante, no lugar da
  confiança na primeira vez — os fabricantes como raiz.
- (d) **Aceitar**: a posse física fora do modelo de ameaça, por escrito —
  o de hoje.

**Os riscos.**

- (a) depende do firmware de cada máquina e de alguém inscrever a chave.
  O iniciador não se atualiza pela A/B — uma versão nova dele vai por um
  provisionamento da ESP —, e assiná-lo é assinar cada provisionamento.
  Sozinho, não protege os selos: outro sistema que o firmware aceite ainda
  os abre.
- (b) a medição muda quando muda o que ela cobre — o firmware, o
  iniciador — e tranca os selos: precisa de um caminho de recuperação, que
  não pode virar a porta dos fundos — e reinstalar perde tudo. O registro
  de eventos da medição tem de ser conferido. O OVMF, o AAVMF e o `swtpm`
  precisam entregar o que o iniciador mede: a conferir nas duas
  arquiteturas.
- (b2) concentra numa chave o que hoje pede o quórum.
- (c) a lista de fabricantes muda, e o `swtpm` da bancada não tem cadeia
  de fabricante.
- Todas mudam a política dos selos que o B2 e o ICP-5 fecharam sem
  medição. O B2 deixou isso de fora de propósito — "prendê-lo à medição do
  boot é o boot seguro, que fica fora daqui" —, e o ICP.md chama o boot
  medido de decisão nova. Não é reabrir a escolha do B2 — a chave nasce no
  primeiro boot e fica no TPM —, mas é mudar o que abre o selo: por isso é
  [C].

**O impacto.** O iniciador (medir; na (a), conferir a assinatura); o kernel
— `tpm.rs`, `identidade.rs`, a persistência e o cofre: as políticas dos
selos e a reconciliação do boot —; a atualização (selar de novo ao armar,
na (b1)); o `xtask` — as bancadas com o `swtpm` medindo, a imagem de
produção —; as máquinas de referência; a documentação de OPERACAO,
ATUALIZACAO e PERSISTENCIA.

**A recomendação.** (b) com (b1): é o que fecha a exposição — os segredos
presos ao código conferido — sem mudar quem confia em quê na atualização.
A (a) depois, como opção do operador, nas máquinas cujo firmware a aceite;
a (c) depois das duas; a (b2) não, sem uma decisão à parte.

**O plano de validação.** A bancada com o `swtpm` medindo, nas duas
arquiteturas: um kernel mudado no slot não abre a identidade nem as
chaves; a atualização A/B arma, sela de novo e boota a versão nova com os
segredos, e a volta sozinha do iniciador também; uma medição do firmware
mudada, simulada, recusa, e o caminho de recuperação é o testado; a queda
de energia em cada fronteira do selar de novo; as mutações — o kernel não
medido, a política sem a medição, o selar de novo pulado, o selar de novo
antes do quórum —; o adversário; a CI completa.

**O que não espera.** Medir o que o OVMF, o AAVMF e o `swtpm` entregam — o
registro de eventos, os PCRs — e quanto o iniciador cresce para medir o
kernel: os dados da decisão.

**As fechadas que ela toca.** O B1 — a atualização A/B, a chave de quem
publica, o quórum `system.update`, o piso de geração. O B2 — a identidade
nasce no primeiro boot, selada neste TPM, e nunca se clona. O ICP-5 — a
custódia continua do kernel. O grupo C — o pânico deixa a máquina parada e
inspecionável: nada de reinício automático quando a medição recusa.

### R13-CONSENT

**O consentimento — a Pessoa perguntada, e o registro que ela lê.**
Decidido junto com a [ALC-TEMP](#alc-temp).

**O problema.** A fase 13 promete três coisas: quem pediu — a Pessoa na
frente da máquina ou o agente pelo canal —, o que foi feito, e um registro
que a Pessoa possa ler depois e desfazer. As duas primeiras existem: a
auditoria grava o titular, a sessão, o processo e o programa de cada
decisão, e o console diz `executado: … (agente N)` ou `(pessoa)`. Falta
perguntar: "um `set_value` do agente troca o que a pessoa estava
digitando, e nada pergunta a ela antes" (README, "O que ainda não há") —
hoje, o que separa os dois é o arrendamento, e "pessoa e agente estão no
mesmo nível". E falta o registro que a Pessoa lê: o `audit.tail` exige
`audit.read`, que o `sistema`, a segurança e o administrador têm — o
`observador` e o `operador`, não.

**A exposição de hoje.** Baixa: um agente com `ui.act` edita o campo que a
Pessoa largou — passado o arrendamento dela — sem perguntar, e a edição
fica gravada; a Pessoa não lê o que fizeram em nome dela.

**As evidências.** O [Roteiro](../README.md#roteiro), fase 13; [Operar por
uma pessoa](../README.md#operar-por-uma-pessoa) — "O que ainda não há";
[Coordenação](../README.md#coordenação); [OPERACAO, Os comandos de todo
dia](OPERACAO.md#os-comandos-de-todo-dia) — quem tem `audit.read`;
[USABILIDADE, Decisões novas](USABILIDADE.md#decisões-novas--para-quem-decide)
— a seção 12 do pedido de usabilidade, "delegação autorizada, lease
temporário, expansão autorizada"; e o precedente do
[D8](PAREAMENTO.md#a-decisão-dn-1-opção-a): a Pessoa cria, sem o
administrador, uma relação cujo papel cabe no dela.

**As alternativas.**

- (a) **(minha, pelo precedente do quórum)** O consentimento como condição
  da política: a política marca as permissões que, pedidas por um agente
  sobre o que é da Pessoa, pedem a confirmação dela no caminho dela
  (DT-1); o gate decide de novo com a confirmação, como decide com um
  quórum. Uma decisão que espera alguém é um desfecho novo no gate.
- (b) **A expansão temporária, por titular** — a [ALC-TEMP](#alc-temp), da
  USABILIDADE: uma entrada da política com prazo — esta identidade, esta
  permissão, este recurso, até tal tempo lógico —, que vence pelo tempo
  lógico e sobrevive a um boot. Dada pelo administrador, com prova; e
  **(minha, pelo precedente do D8)** pela Pessoa, para o que é dela,
  contida no papel dela. Consentir é dar a entrada; o gate decide como
  sempre, com ela.
- (c) **(minha)** Só o registro: a Pessoa lê a auditoria do que foi feito
  em nome dela, ou no que é dela — um alcance novo de leitura —, e nada se
  pergunta antes.
- (d) Nada: como hoje.

**Os riscos.**

- (a) põe no gate uma decisão que espera uma pessoa — a automação de um
  agente para no humano —, e, sem a DT-1, a confirmação pode ser imitada
  por outra janela.
- (b) é autoridade dada por quem não é administrador. O teto (o papel da
  Pessoa), a enumeração (sem curinga) e o fim (o prazo, a revogação da
  Pessoa ou do agente, a política seguinte) têm de ser da própria
  política, e não de uma tabela ao lado — senão é uma segunda autorização.
  O tempo lógico pode parar, depois de um salto do civil para trás: a
  entrada dura mais que o prazo no relógio. A entrada e o vencimento vão
  ao journal.
- (c) mostra à Pessoa registros que nomeiam outros: o alcance tem de ser
  só o dela, e o que uma resposta cala — o mesmo `DENY_RESOURCE` para o
  que não existe e o que é de outro — não pode vazar pelo registro.

**O impacto.** A política (uma linha com prazo, de uma identidade, e a
conta do teto); o gate (lê as entradas, e o prazo pelo tempo lógico); a
persistência (a entrada e o vencimento no journal, com a decisão que os
autorizou); o console (a Pessoa dá e tira a entrada, depois da DT-1); os
comandos da auditoria (a leitura da Pessoa); a documentação de
USABILIDADE, OPERACAO e do README.

**A recomendação.** (b) + (c), depois da DT-1: consentir é a Pessoa dar,
pelo caminho dela, uma entrada com prazo da política — enumerada, contida
no papel dela, gravada e vencida pelo tempo lógico —, e ela lê o registro
do que foi feito com ela. A (a) não, por ora: uma decisão que espera é um
mecanismo novo no gate, e a (b) dá o mesmo controle sem ele. Não se
delega identidade: o agente continua ele mesmo, com mais um recurso por um
tempo.

**O plano de validação.** No hospedeiro, a política: o prazo, o teto, a
falta de curinga, o vencimento pelo tempo lógico, o lógico parado. Na
suíte: dar, usar e vencer; a revogação da Pessoa e a do agente, que apagam
a entrada; a entrada além do papel, recusada; a leitura da Pessoa, sem o
registro dos outros. Na bancada de persistência: a entrada e o vencimento
através do corte de energia e do boot. As mutações — o prazo ignorado, o
teto ignorado, a entrada que sobrevive à revogação, a leitura sem o filtro
do titular. O adversário: passar do teto, usar uma entrada vencida,
mantê-la depois da revogação. As duas arquiteturas; a CI completa.

**O que não espera.** Nada de código: a gramática e a conta da (b)
dependem da decisão. O desenho da leitura da Pessoa (c) pode ser escrito
como proposta.

**As fechadas que ela toca.** Nenhum `ALLOW(*)`: a entrada é enumerada. A
Policy como fonte da decisão: a entrada é da política. Nenhuma autorização
paralela. [O teto não é posse](../README.md#o-teto-não-é-posse): o papel de
teto do administrador não se exerce. E a R1: a revogação de quem deu a
entrada, ou de quem a recebeu, não tem volta.

### M-EXEC

**O `exec` e a malha do processo.**

**O problema.** Na troca de imagem, os endpoints do processo continuam
abertos com a identidade do programa que os ofereceu — o nome, o resumo e
o editor da imagem anterior, que a descoberta mostra —; o que esperava
neles passa à imagem nova, que também continua com a janela de nonces do
processo. Cada operação da imagem nova passa pelo gate com o manifesto
dela, no mesmo titular: nenhuma autoridade a mais. Mas a identidade do
endpoint deixa de ser a do programa que roda — e a malha existe para que
quem procura escolha pelo que o programa **é**.

**A exposição de hoje.** Baixa: no mesmo titular, a descoberta e a
auditoria atribuem a um programa o que outro faz; quem escolhe pelo resumo
escolhe errado.

**As evidências.** [MALHA, A identidade de um
programa](MALHA.md#a-identidade-de-um-programa) e [Revogação e
fim](MALHA.md#revogação-e-fim); [SDK, Limites
conhecidos](SDK.md#limites-conhecidos) — as designações e os avisos na
fila saem no `exec` (NS17, NS36), e os endpoints ficam; o precedente do
[FLUXOS, Os estados](FLUXOS.md#os-estados): a ponta de um fluxo é do
processo e não sobrevive ao `exec` (`o programa mudou`), encerrada dentro
da ordem das gravações, logo depois do ponto sem volta — o trabalho do
AE-1; o caso `malha: o impostor nao alcanca o que e do outro`.

**As alternativas.** As duas primeiras são as do README.

- (a) Fechar os endpoints no `exec`, como no fim do processo: o que
  esperava neles é anulado (`voided`), e o fecho vai à auditoria com o
  motivo.
- (b) Mudar a identidade deles para a da imagem nova: a descoberta passa a
  mostrar o programa que roda.
- (c) Como hoje, documentado.

**Os riscos.**

- (a): o programa que se troca por outro — ou por si mesmo — perde os
  endpoints e oferece de novo; quem mandou vê `voided`, e manda de novo.
- (b): quem escolheu pelo resumo antes da troca fala com outro programa
  sem saber; o registro da oferta diz um programa, e o endpoint outro — a
  cadeia de ids da auditoria precisa de um elo novo.
- (c): a atribuição errada continua, e cresce na fase 15, com um endpoint
  visto de outro Duke.

**O impacto.** `kernel/src/malha.rs` e o caminho do `exec` em
`kernel/src/usuario`, que já encerra ali os fluxos da ponta; o registro
`fabric.withdraw` com o motivo; o SDK e a MALHA na documentação.

**A recomendação.** (a): o mesmo ciclo de vida da ponta de um fluxo — um
objeto da malha é do processo **e** do programa que o criou —, e a
identidade de um endpoint volta a ser sempre a do programa que roda. A
janela de nonces fica: é do canal de quem manda, o processo, e não do
programa — uma janela nova deixaria a imagem nova repetir os nonces da
anterior.

**O plano de validação.** Um caso: o programa oferece, recebe uma entrega
pendente e troca de imagem; o endpoint some da descoberta, a entrega fica
`voided`, o fecho vai à auditoria com o motivo, e a imagem nova oferece de
novo e recebe. A mutação — o endpoint que sobrevive ao `exec` — reprova.
As duas arquiteturas; a bancada `cargo xtask sdk`, que não deve mudar.

**O que não espera.** Conferir quais programas da imagem oferecem um
endpoint e trocam de imagem: os dados da decisão.

**As fechadas que ela toca.** A DF-1 — o fluxo é um objeto da malha,
entre dois processos do titular. O DS-1 — o aviso só sinaliza: a troca
larga as designações antes do resto, como hoje.

## As outras

Na ordem recomendada. Cada uma: o problema, as alternativas, a
recomendação provisória e o que destrava.

### ALC-TEMP

**A expansão temporária de alcance, por titular.** Proposta com o
[R13-CONSENT](#r13-consent), alternativa (b).

- **O problema.** Hoje o alcance é do papel, e o que muda o papel é
  `policy.write` e `policy.assign`, com prova, até a próxima mudança. Uma
  expansão temporária, por titular — "esta pessoa, este recurso, por uma
  hora" — é um conceito que a política não tem: uma entrada com prazo, de
  uma identidade e não de um papel, que vence pelo tempo lógico e
  sobrevive a um boot. "Isso não se infere das invariantes" ([README,
  Decisões pendentes](../README.md#decisões-pendentes);
  [USABILIDADE](USABILIDADE.md#decisões-novas--para-quem-decide)).
- **As alternativas.** (a) A entrada com prazo, por identidade, na
  política — a da USABILIDADE. (b) **(minha)** A atribuição de um papel
  com prazo — o `policy.assign` que vence —, sem entrada por recurso. (c)
  Nada: o administrador muda o papel e o desfaz à mão.
- **A recomendação provisória.** (a), como parte do consentimento.
- **Destrava.** O consentimento da fase 13.

### A9-RESUMO

**O tamanho do resumo na descrição de um programa** — o achado 9 do
adversário do passo 1.

- **O problema.** A auditoria e o NSF nomeiam um programa pelo nome, pelos
  8 dígitos hexadecimais do começo do BLAKE2s do executável — 32 bits — e
  pelo editor. Com o mesmo nome e o mesmo editor, dois executáveis com os
  mesmos quatro primeiros bytes do resumo têm a mesma descrição: uma
  segunda pré-imagem de 32 bits, uns 2^32 resumos. O grafo do NSF já
  separa o código de fora do da imagem, e um editor de outro ([README,
  Decisões pendentes](../README.md#decisões-pendentes); [SEGURANCA, O
  modelo de evento](SEGURANCA.md#o-modelo-de-evento)).
- **As alternativas.** (a) Aumentar o resumo — 16 dígitos, 64 bits —, que
  muda o formato do detalhe e a conta do teto de 96 bytes. (b) **(minha)**
  O resumo inteiro num registro só, o do nascimento do processo. (c)
  Aceitar.
- **A recomendação provisória.** (a), medindo quantos registros chegam ao
  teto com o resumo maior — a descrição já encolhe o nome e o editor antes
  do motivo.
- **Destrava.** Nada do roteiro; fecha um resíduo do passo 1.

### A1-4

**O que a recusa da cota mostra** — o achado A1-4 do adversário da
alternativa 1.

- **O problema.** A recusa — "cota de processos do papel: N de M" — conta
  os mortos que esperam o coletor, e o `process.list` não os mostra: quem
  a ouve vê menos processos do titular na lista ([README, Decisões
  pendentes](../README.md#decisões-pendentes)).
- **As alternativas.** (a) Dizer na recusa quantos dos contados são
  mortos que esperam o coletor — muda o texto da auditoria, como a
  correção (5) da [COTA-SOMA](#cota-soma), que o README trata como [B].
  (b) Mostrar os mortos no `process.list` — muda uma saída documentada.
  (c) Nada.
- **A classificação.** Pela 5.3 de 17/11/2026, nenhuma das duas parece
  [C]: o texto do detalhe não é contrato ([SDK, O contrato
  v2](SDK.md#o-contrato-v2-ds-2)), e uma saída do `process.list` não é
  semântica de segurança. O README a deixou "para uma decisão à parte";
  cabe ao dono dizer se ela volta ao [B].
- **A recomendação provisória.** (a).
- **Destrava.** O diagnóstico da cota.

### SDK-CANAL

**O canal sem nome** — os nomes previsíveis do laço.

- **O problema.** O `Laco::novo` tenta 16 nomes previsíveis
  (`laco-<id>`, `laco-<id>-1`…); quem os tomar todos — 8 processos de uma
  sessão de operador, com 2 canais cada — impede o laço daquele processo.
  `escutar` não reserva nome nem passa pelo gate: a mesma raiz dos nomes
  `terminal` e `janelas` da [DT-1](#dt-1) ([SDK, Limites
  conhecidos](SDK.md#limites-conhecidos)).
- **As alternativas.** (a) O canal sem nome — o kernel dá a chave, sem um
  nome que outro tome —, crescimento do contrato v2: "decisão revisada",
  pela regra do DS-2. (b) Aceitar.
- **A classificação.** A regra é a do DS-2 — crescer o contrato é decisão
  revisada —; pela 5.3, talvez não seja [C]: não toca identidade,
  autoridade nem auditoria. Cabe ao dono.
- **A recomendação provisória.** (a), junto com a regra dos nomes da DT-1.
- **Destrava.** Um limite do SDK.

### AUD-ANEL

**Os registros do boot que saem do anel antes do journal** — o achado 4
do adversário do B4 da auditoria.

- **O problema.** A continuação leva só o anel da cadeia do boot: mais de
  1024 decisões antes de o journal ser lido perderiam as primeiras, sem
  lacuna. Hoje o boot faz uns poucos registros antes
  ([PERSISTENCIA](PERSISTENCIA.md#a-reconstrução-da-auditoria-no-boot-b4),
  "O que o adversário achou").
- **As alternativas.** (a) Marcar a perda — "uma lacuna com o elo de
  outra numeração — semântica nova, uma decisão [C]". (b) Aceitar, como
  limitação escrita: o de hoje.
- **A recomendação provisória.** (b), enquanto o boot fizer poucos
  registros antes do journal; (a) se um incremento puser decisões no boot
  antes dele.
- **Destrava.** Nada do roteiro.

### P-HISTORIA

**A história da autoridade que cresce sem fim** — do 7.6 e do 7.7.

- **O problema.** A base do journal carrega todas as mudanças de
  autoridade, com as decisões, desde a instalação — "é assim que nenhuma
  revogação se perde" —, e só a política é deduplicada. Uma instalação com
  muitas operações acaba com uma base que não cabe na outra região: a
  compactação não acontece, a região enche, e a persistência fica
  indisponível — fechada, mas parada. Com regiões de 8 MiB, são dezenas de
  milhares de operações ([PERSISTENCIA, Como ficou
  (7.6)](PERSISTENCIA.md#como-ficou-76), "O que fica para depois").
- **A classificação.** O PERSISTENCIA não a chama de decisão — "fica para
  quando for preciso" —; resumir a história muda o que a persistência
  guarda das decisões: pela 5.3, [C]. A classificação é deste dossiê.
- **As alternativas.** (a) Resumir a história — o estado final de cada
  credencial, com a decisão que o fixou —, "uma mudança de formato"; as
  lápides ficam inteiras (R1). (b) Aceitar, até uma instalação chegar
  perto do teto.
- **A recomendação provisória.** (b), medindo quanto a base cresce por
  operação, para saber quando a (a) vira necessária.
- **Destrava.** A vida longa de uma máquina.

### R13-DESFAZER

**O desfazer** — "um registro que a pessoa possa ler depois e desfazer"
([Roteiro](../README.md#roteiro), fase 13).

- **O problema.** O que se desfaz hoje: as contenções, cada uma com o seu
  inverso ([USABILIDADE](USABILIDADE.md#a-contenção-reversível)), e uma
  subárvore do armazém, de uma cópia. O que não se desfaz, de propósito:
  uma revogação ([R1](PERSISTENCIA.md#r1-a-revogação-é-uma-lápide-permanente):
  não existe desrevogar), o journal
  ([R6](PERSISTENCIA.md#r6-restauração-de-um-estado-anterior): a âncora
  recusa um estado anterior), e o estado de autoridade de uma cópia
  ([B5-4](#b5-4)). O armazém guarda a versão de cada arquivo, e não o
  conteúdo de antes.
- **As alternativas.** (a) **(minha)** Desfazer como uma operação nova,
  para a frente, por tipo de operação reversível — a compensação, gravada
  com a decisão dela —, e nunca a volta do journal. (b) **(minha)** Guardar
  por um tempo o conteúdo de antes dos arquivos do armazém, para desfazer
  uma escrita — muda o que o armazém guarda, e as cotas. (c) Só o que
  existe.
- **A recomendação provisória.** (a), só para dados e para operações
  reversíveis, depois do [R13-CONSENT](#r13-consent); a (b) se a (a)
  precisar.
- **Destrava.** Fecha a fase 13.

### R12-SIMD

**O SIMD nos processos** — "o contrato dos registradores"
([Roteiro](../README.md#roteiro), fase 12).

- **O problema.** Os programas não usam SIMD nem AES-NI: o kernel não
  salva os registradores de SIMD de um processo quando troca de processo,
  e dois programas que os usassem corromperiam um o estado do outro, sem
  erro nenhum. Os alvos (`x86_64-unknown-none`,
  `aarch64-unknown-none-softfloat`) e as opções dos pacotes de cifra
  (`programas/.cargo/config.toml`) o garantem, e o `xtask` confere o kernel
  (`conferir_sem_simd`). O custo: o ChaCha20-Poly1305 em software, 317
  MiB/s no hospedeiro, contra 104 do AES-128-GCM — por isso ele vai
  primeiro ([O TLS de um programa](../README.md#o-tls-de-um-programa)) —, e
  o SHA-256 do BLS do IC, em software ([ICP](ICP.md#as-bibliotecas)).
- **O que a decisão fixa.** Se o kernel salva o estado de SIMD de cada
  processo, e quando; quanto isso custa em memória por fio e em tempo de
  troca; e a forma binária dos programas — os alvos e as opções —, que o
  contrato v2 inclui.
- **As alternativas.** O roteiro só nomeia a decisão; as duas primeiras
  são **(minhas)**. (a) Salvar sempre, em toda troca de processo — o
  estado de um processo nunca fica no registrador enquanto outro roda: a
  troca preguiçosa é a do vazamento de estado de ponto flutuante entre
  processos conhecido desde 2018 (o LazyFP). (b) Salvar só para os
  programas que o declaram no manifesto. (c) Como hoje.
- **A recomendação provisória.** (a), medida — a memória por fio e o tempo
  da troca —, e só depois a mudança dos alvos dos programas, numa versão
  da interface nativa: um programa compilado com SIMD num kernel que não o
  salva corrompe sem erro.
- **Destrava.** As otimizações de cifra da fase 12; o TLS e o IC mais
  depressa.

### R12-mTLS

**O certificado do cliente no TLS** — "um domínio de assinatura novo"
([Roteiro](../README.md#roteiro), fase 12).

- **O problema.** O TLS de um programa não manda certificado ("sem
  certificado de cliente"). O mTLS faz o programa provar uma identidade ao
  servidor, e a assinatura do aperto (o `CertificateVerify`) precisa de
  uma chave guardada pelo kernel. O registro de domínios tem um só,
  `ic-request` ([ICP, O domínio](ICP.md#o-domínio)).
- **As alternativas.** (a) Um domínio novo no registro — o do
  `CertificateVerify` do cliente no TLS 1.3 —, com as chaves de assinatura
  das identidades de hoje (`key.sign`, o mesmo gate, a mesma auditoria), o
  certificado como arquivo do programa, e a linha `dominios` da política
  dizendo que papéis o usam. (b) **(minha)** Uma chave à parte, só do TLS,
  com outra custódia. (c) Nada.
- **Os riscos de (a).** A separação de domínio é o que impede uma
  assinatura do TLS de valer como um pedido do IC, e o contrário. O
  `key.sign` assina um resumo de 32 bytes, e **(minha, a conferir)** as
  suítes com SHA-384 têm um resumo do aperto de 48. E quem emite o
  certificado — o operador, uma autoridade de fora — é uma confiança nova.
- **A recomendação provisória.** (a), quando houver um servidor que peça o
  certificado.
- **As fechadas.** O grupo C: nada de mTLS para o IC. O certificado do
  servidor prova um nome ao programa e não autoriza nada. Nenhuma chave
  exportada.
- **Destrava.** A infraestrutura da fase 12. A gestão de certificados, que
  o roteiro põe antes do mTLS, não está nem entre os feitos nem entre os
  que pedem decisão: conferir o estado dela.

### R12-PROXY

**O *proxy*** — "um destino que o gate não vê" ([Roteiro](../README.md#roteiro),
fase 12).

- **O problema.** O gate decide o destino de cada conexão, e o protocolo é
  do programa. Por um *proxy*, o programa conecta ao *proxy*, e o destino
  de verdade vai dentro da conversa — o `CONNECT` —, que o gate não vê. O
  HTTP/2 já recusa juntar dois nomes numa conexão pela mesma razão
  ([O HTTP/2](../README.md#o-http2), "Uma conexão por origem").
- **As alternativas.** (a) **(minha)** O *proxy* como um destino qualquer,
  e o destino de verdade fora da decisão: o gate deixa de decidir o
  destino. (b) **(minha)** Os dois decididos — o *proxy* e o destino de
  verdade como recurso —, com o `CONNECT` feito por um componente em que o
  gate confia, e não pelo programa que pede. (c) Nada: o de hoje.
- **A recomendação provisória.** (c) até uma necessidade concreta; nunca a
  (a).
- **As fechadas.** As decisões consolidadas do
  [SEGURANCA](SEGURANCA.md#as-decisões-consolidadas): o HTTP é do
  programa, sem HTTP no kernel, e o gate decide o destino.
- **Destrava.** A infraestrutura da fase 12.

### R12-QUIC

**O HTTP/3 e o QUIC** — "o HTTP/3, que depende do QUIC e começa por uma
avaliação" ([Roteiro](../README.md#roteiro), fase 12).

- **O problema.** A avaliação não é [C]: é trabalho [B], e começa já
  (5.4). O que ela precisa responder para virar uma decisão — **(minhas)**:
  a migração da conexão e o endereço preferido do servidor, em que a
  conversa muda de destino sem o gate, o mesmo ponto do *proxy*; o 0-RTT,
  dados que se repetem; e a associação UDP de hoje, "que só conversa com o
  destino decidido", diante de uma conexão que não é do endereço.
- **A recomendação provisória.** A avaliação primeiro; depois, o QUIC sem
  migração e sem 0-RTT, se ele couber no destino decidido.
- **As fechadas.** O grupo C: nada de HTTP/3 nem de QUIC para o IC.
- **Destrava.** A infraestrutura da fase 12.

### R12-IC-TPM

**A chave de assinatura dentro do TPM** ([ICP, O que não existe
ainda](ICP.md#o-que-não-existe-ainda)).

- **O problema.** A semente das chaves de assinatura está selada no TPM em
  repouso (ICP-5), mas a privada mora na memória do kernel, e quem assina
  é ele. Assinar dentro do TPM tiraria a privada da memória.
- **As alternativas.** (a) Como está: a custódia do kernel, a semente
  selada. (b) A chave gerada e usada dentro do TPM, depois do gate — um
  modelo de custódia novo.
- **O risco de (b) — (minha, a conferir).** O Ed25519 não está entre o
  que os TPM 2.0 em uso costumam implementar; com outro algoritmo, a chave
  dá outro Principal — e "outra identidade ou Principal" é do grupo C. E o
  TPM é lento para assinar cada pedido.
- **A recomendação provisória.** (a); voltar a ela depois da
  [R13-BOOT](#r13-boot), conferido o que o TPM da máquina de referência e
  o `swtpm` assinam.
- **Destrava.** A fase 12 (Web3); a custódia que a R12-IC-VALOR pede.

### R12-IC-VALOR

**A rede principal com valor e com canister** ([ICP, Na rede
principal](ICP.md#na-rede-principal)).

- **O problema.** Na rede principal, o Duke só lê: a consulta anônima e as
  assinadas do saldo do `gestor`. "Criar, instalar e carregar lá move
  valor e não volta atrás: fica para quando houver uma chave com cycles e
  a decisão de gastá-los — e nunca na CI." A política padrão não alcança
  destino nenhum dela, e a `carteira` e a `implantacao` só andam nas redes
  da bancada.
- **As alternativas.** (a) Como está. (b) Uma identidade dedicada, com um
  orçamento escrito, os destinos da rede principal enumerados na política
  de uma máquina, as proteções do `gestor`, e a autorização do dono para
  gastar — uma operação irreversível
  ([5.6](../CLAUDE.md#56-o-que-a-autonomia-não-autoriza)). (c) A (b) só
  depois da [R13-BOOT](#r13-boot) e da [R12-IC-TPM](#r12-ic-tpm).
- **A recomendação provisória.** (c).
- **Destrava.** A fase 12 (Web3); a consulta replicada na rede principal,
  que espera um canister do projeto lá.

### R12-IC-NOS

**Os nós da rede principal pela árvore de estado** ([ICP, O que fica de
fora](ICP.md#o-que-fica-de-fora)).

- **O problema.** `icp-api.io` é servido por nós que giram — quatro
  endereços em pouco mais de uma hora. A política enumera os IPv4 que o
  pré-voo viu; quando a máquina recebe outro, o gate recusa, e a fumaça
  real falha fechada. Descobrir os nós pela árvore de estado
  (`api_boundary_nodes`) "seria uma decisão nova".
- **As alternativas.** (a) Como está: o administrador escreve o nó novo
  pelo `policy.write`. (b) **(minha)** O programa descobre os nós pela
  árvore de estado, e o administrador os escreve na política: a ferramenta
  muda, a política não. (c) **(minha)** A política aceita os destinos que a
  raiz do IC certifica — uma fonte nova de destino, que esbarra na Policy
  como fonte da decisão.
- **A recomendação provisória.** (b).
- **Destrava.** A fumaça real da rede principal, que fecha sempre.

### R12-IC-OUTROS

**O resto do IC.** O [ICP](ICP.md#o-que-não-existe-ainda) lista o que não
existe, "e cada um é uma decisão nova quando vier": o ICRC-2 e o ICRC-3; o
selo de código do Duke valendo para o módulo implantado no IC; o `icp-cli`
dentro do Duke; o CDK; o compartilhamento de chaves; exportar ou importar
uma privada. Nenhum tem necessidade demonstrada. Exportar uma privada
esbarra na custódia (1.7: nenhuma chave exportada); compartilhar uma chave
entre identidades, na delegação de identidade (5.3); as delegações, as
chaves de sessão, a EVM e o HTTP/3 do IC são do grupo C (ver [as
fechadas](#as-fechadas-que-não-se-reabrem)). Recomendação provisória:
nenhum, até uma necessidade.

### R15-HANDOFF

**O handoff.** O roteiro: "O handoff, os recursos remotos, a presença, a
continuidade e os pacotes são os marcos seguintes, e cada um pede uma
decisão própria antes" ([Roteiro](../README.md#roteiro), fase 15;
[MALHA, O que fica de fora](MALHA.md#o-que-fica-de-fora)). As fontes não
os definem além do nome; o sentido abaixo é o comum.

- **O problema.** Passar uma atividade de um Duke a outro da mesma Pessoa.
- **As fechadas que ele esbarra.** Nenhuma identidade migrada; cada Duke é
  um principal próprio (D1, D2); a autoridade remota é a composição Pessoa
  ∩ relação ∩ `remoto` (D4, DF-5); nada de um fluxo persiste, e a retomada
  está fora ([FLUXOS](FLUXOS.md#o-que-fica-de-fora)); sem
  armazenamento-e-envio (D5).
- **As alternativas.** (a) **(minha)** O handoff como protocolo de
  programa, sobre os fluxos: o programa de um Duke manda o estado ao do
  outro, que continua — nada novo no kernel. (b) **(minha)** Um objeto de
  handoff no kernel, que leva um endpoint ou uma sessão de um Duke a outro
  — esbarra em "nenhuma identidade migrada" se levar a sessão. (c) Nada.
- **A recomendação provisória.** (a), depois da [M-EXEC](#m-exec).

### R15-REMOTOS

**Os recursos remotos.**

- **O problema.** Usar, deste Duke, um recurso de outro da mesma Pessoa.
- **As fechadas que ele esbarra.** O conjunto fechado de mensagens do
  enlace (D3); a autoridade composta no destino (D4, DF-5); a Fabric não é
  autoridade.
- **As alternativas.** (a) **(minha)** O recurso servido por um programa do
  outro Duke, por uma intenção da malha e um fluxo — nada novo no kernel.
  (b) **(minha)** Um domínio próprio no enlace para uma classe de recurso,
  como a DF-4 fez para o fluxo. (c) Nada.
- **A recomendação provisória.** (a) primeiro, medindo o que falta.

### R15-PRESENCA

**A presença.**

- **O problema.** Saber se um Duke da Pessoa está ao alcance, agora.
- **As fechadas que ele esbarra.** A D7: o endereço é configuração, e não
  há descoberta; a descoberta local e o broadcast estão fora
  ([ENLACE](ENLACE.md#o-que-fica-de-fora),
  [PAREAMENTO](PAREAMENTO.md#o-que-fica-de-fora)).
- **As alternativas.** (a) **(minha)** A presença só entre os já
  relacionados, pelo endereço da relação — uma mensagem a mais no conjunto
  fechado do enlace. (b) A descoberta local — esbarra na D7, e não se
  propõe aqui. (c) Nada.
- **A recomendação provisória.** (a).

### R15-CONTINUIDADE

**A continuidade.**

- **O problema.** Retomar o trabalho — um fluxo, uma conversa — depois de
  uma queda, ou noutro Duke.
- **As fechadas que ele esbarra.** O fluxo é volátil, e a retomada, a
  migração e a recuperação estão fora
  ([FLUXOS](FLUXOS.md#o-que-fica-de-fora)); um fluxo que acaba não volta
  ([SDK](SDK.md#o-que-não-existe)).
- **As alternativas.** (a) **(minha)** A continuidade no protocolo do
  programa: um fluxo novo, e o programa retoma de onde parou. (b)
  **(minha)** Fluxos que se retomam no kernel — mudam o que o DN-2 entregou
  como volátil. (c) Nada.
- **A recomendação provisória.** (a), depois da [M-EXEC](#m-exec).

### R15-PACOTES

**Os pacotes.**

- **O problema.** "Não há gerenciador de pacotes, repositório,
  dependências entre programas nem atualização de programas: o programa é
  um arquivo selado" ([SDK, O que não existe](SDK.md#o-que-não-existe)).
- **As fechadas que ele esbarra.** O selo de código da fase 13 não tem
  revogação de um selo nem de uma versão, nem cadeia de editores; a
  confiança é do papel no editor ([O código de fora da
  imagem](../README.md#o-código-de-fora-da-imagem)); o contrato v2.
- **As alternativas.** (a) **(minha)** O `instalador` de hoje, com a versão
  no manifesto e uma lista de revogados assinada pelo editor — uma
  confiança nova. (b) Os programas só pela atualização da imagem (B1). (c)
  Nada.
- **A recomendação provisória.** (b) até uma necessidade; a (a) depois,
  decidida com o anti-rollback dos programas.

### B5-1

**Restaurar num volume recusado** ([OPERACAO, grupo
B](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b)).

- **O problema.** Um volume cujo journal dos metadados não chega ao
  registro confirmado — estragado, trocado, de outro tamanho — fica
  indisponível. Restaurar exigiria recriá-lo — sobrepor uma recusa da
  âncora — e continuar o contador de versões do armazém, que o volume
  perdido levou: o journal de estado não guarda a próxima versão.
- **As alternativas** (do OPERACAO). (a) A próxima versão em
  `ARMAZEM_CONFIRMADO` — um formato novo da entrada — e a recriação por
  uma operação autorizada. (b) Aceitar versões que repetem números já
  lidos.
- **A recomendação provisória.** (a). A (b) quebra "uma versão nunca se
  repete".
- **Destrava.** O grupo B da fase 14.

### B5-2

**Recuperar depois de perder o disco.**

- **O problema.** O selo da identidade mora no disco; sem ele, a máquina
  reinstalada nasce com outra identidade, e a cópia — cifrada por uma
  derivação da antiga — não abre.
- **As alternativas** (do OPERACAO). (a) Uma chave de custódia do operador
  para as cópias — uma confiança nova. (b) Uma cópia do selo — reabre o
  B2, e não se propõe aqui.
- **A recomendação provisória.** Nenhuma por ora; se vier, a (a).

### B5-3

**Restaurar noutra máquina, ou migrar.**

- **O problema.** Exigiria confiança entre máquinas — uma recifrar a cópia
  para a outra — e uma semântica de migração que não existe.
- **As fechadas que ele esbarra.** Migrar esbarra numa invariante — 1.7,
  nenhuma identidade clonada ou migrada —, e não se propõe. Restaurar uma
  imagem não pode dar a duas máquinas a mesma identidade.
- **As alternativas.** (a) **(minha)** Só os dados: a cópia recifrada pela
  relação entre dois Dukes da mesma Pessoa (o enlace e o D8) — uma
  semântica nova sobre a relação. (b) Nada.
- **A recomendação provisória.** (a), só se houver necessidade.

### B5-4

**Restaurar o estado de autoridade.**

- **O problema.** Pessoas, credenciais, política, lápides, chaves e
  mensagens de uma fotografia anterior desfariam revogações — a R1: não
  existe desrevogar — e voltariam o journal atrás — a R6: a âncora recusa.
  Exigiria uma política de replay nova.
- **A recomendação provisória.** Não. O estado de autoridade se refaz por
  operações administrativas, para a frente.

## As fechadas que não se reabrem

O que é CLOSED e toca nestes assuntos. Nenhuma entrada deste dossiê as
propõe de novo; quando uma esbarra numa delas, a fechada é restrição.

- **As invariantes** ([1.7](../CLAUDE.md#17-as-invariantes-permanentes)):
  nenhuma ABI do Linux; a Pessoa como identidade durável; a autoridade
  carregada pelo processo; system/root como autoridade máxima, sem
  curinga; as permissões enumeradas, sem `ALLOW(*)`; um Gate, uma cadeia
  de autorização, nenhuma autorização paralela; a Policy como fonte da
  decisão; a auditoria e a proveniência; a Fabric, os fluxos e os avisos
  nunca como autoridade; o Noise nunca no lugar da autorização; a
  identidade própria de cada dispositivo, nunca clonada nem migrada; a
  custódia das chaves, nenhuma exportada.
- **B1 a B5** ([OPERACAO, grupo
  B](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b)): a atualização A/B,
  com a chave de quem publica, o quórum e o anti-rollback no TPM (B1); a
  identidade que nasce no primeiro boot, selada neste TPM (B2); o botão de
  energia pelo fluxo que o usuário fixou em 28/10 — o evento de hardware
  não é autoridade (B3); a troca da própria senha, provando a atual (B4); a
  cópia só dos dados, sem o estado de autoridade (B5).
- **O ICP-5**: a semente selada no TPM, e a custódia do kernel.
- **D1 a D10 e o Estágio 1** ([ENLACE](ENLACE.md#as-decisões)) — entre
  elas: a identidade do dispositivo é a chave do Duke, sem PKI (D2); a
  autoridade composta no destino (D4); sem armazenamento-e-envio (D5); a
  revogação local, sem propagação (D6); o endereço como configuração, sem
  descoberta (D7). E a porta própria do enlace, a 7071.
- **DN-1 (opção A) e D8** ([PAREAMENTO](PAREAMENTO.md#a-decisão-dn-1-opção-a)).
- **DN-2, com DF-1 a DF-6** ([FLUXOS](FLUXOS.md#as-decisões-df-1-a-df-6)).
- **DN-3, com DS-1 e DS-2** ([SDK](SDK.md#o-contrato-v2-ds-2)): o aviso só
  sinaliza; o contrato só cresce dentro da versão, crescer é decisão
  revisada, e remover é só numa versão maior.
- **A C1** (11/11/2026,
  [PERSISTENCIA](PERSISTENCIA.md#os-leitores-e-o-anexar-a-trava-do-gate-sem-o-alocador)):
  o elo BLAKE2s da auditoria fica com a trava — sem protocolo otimista, sem
  lotes, sem árvore de Merkle. Volta a ser considerada só se uma medida
  mostrar o elo como gargalo relevante.
- **A 14.1** (alternativa A, 7/11/2026) **e a alternativa 1 do A1**
  (8/11/2026) ([Coordenação](../README.md#coordenação)): a cota conta os
  zumbis e os mortos até o recolhimento, e só o coletor recolhe. As
  alternativas não adotadas do A1 ficaram registradas: a (2) segue aberta
  na [COTA-SOMA](#cota-soma), e a (3) é uma mitigação [B].
- **O grupo C** ([OPERACAO](OPERACAO.md#o-que-fica-de-fora-de-propósito-grupo-c)):
  o watchdog e o reinício automático depois de um pânico — o post-mortem é
  decisão fechada —; a ACPI no ARM, as placas ARM físicas, o AHCI e o
  SATA, o USB de armazenamento e as placas de rede além da 82574L; as
  pontes PCI que o firmware não numerou; o IPv6; a ABI do Linux; e, do
  IC, a delegação, as chaves de sessão, outra identidade ou Principal, o
  mTLS, o HTTP/3, o QUIC, a EVM e o SDK — "nada disso tem uma necessidade
  demonstrada". O roteiro (fase 12, Web3) ainda põe as delegações entre os
  incrementos "que pedem, cada um, uma decisão nova", e o
  [ICP](ICP.md#o-que-não-existe-ainda) entre o que é "uma decisão nova
  quando vier"; o grupo C as deixa de fora de propósito. Este dossiê segue
  o grupo C.
- **As decisões consolidadas do tecido de segurança**
  ([SEGURANCA](SEGURANCA.md#as-decisões-consolidadas)): o DNS, o TLS e o
  HTTP são programas, e o gate decide o destino; o certificado prova um
  nome ao programa e não autoriza nada; o NSF recomenda a revogação, e
  quem tem a prova a executa.
- **R1 a R6 da persistência**
  ([R1](PERSISTENCIA.md#r1-a-revogação-é-uma-lápide-permanente),
  [R6](PERSISTENCIA.md#r6-restauração-de-um-estado-anterior)): a revogação
  é uma lápide permanente, e não existe desrevogar; a âncora recusa um
  estado anterior.
- **As decididas pela medida**, que só reabrem com uma medida nova: o gate
  sem cache ([README](../README.md#o-gate-sem-cache)).
