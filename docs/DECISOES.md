# As decisões abertas

Este é o dossiê das decisões [C] que o roteiro do Duke espera: as que
pedem a aprovação explícita do dono do projeto antes da primeira linha
(`CLAUDE.md`, [1.6](../CLAUDE.md#16-as-decisões-a-b-c) e
[5.3](../CLAUDE.md#53-as-decisões-c)). Elas estão espalhadas pelo README e
por `docs/`; aqui ficam juntas, cada uma com os dados para decidir, para
que o dono decida de uma vez e o desenvolvimento siga. O bloco a decidir
agora são os itens 1 a 6 da [ordem](#a-ordem-recomendada): as entradas
curtas dos itens 7 a 12 não são para decidir neste bloco — a recomendação
delas é provisória, e cada uma ganha a proposta completa quando chegar a
vez.

**Nada aqui está decidido.** Recomendar não é aprovar (1.6): cada entrada
diz o que este dossiê recomenda, e nenhuma muda de estado sem a palavra do
dono. Nenhuma se implementa antes da aprovação (5.3). E nenhuma trava o
resto: o trabalho que não depende de uma decisão continua
([5.4](../CLAUDE.md#54-o-trabalho-que-não-espera)) — cada proposta diz o
que não espera.

**Como ler.**

- [O índice](#o-índice) tem uma linha por decisão aberta do dono: o id, a
  decisão, a área de 5.3 que a faz [C], o que ela destrava no roteiro, a
  exposição de hoje — o risco real enquanto ela espera, se há — e a fonte.
- [A ordem recomendada](#a-ordem-recomendada) diz por onde começar, e por
  quê.
- [As propostas completas](#as-propostas-completas) — as cinco primeiras
  da ordem — seguem o formato de 5.3: o problema, as evidências, as
  alternativas, os riscos, o impacto, a recomendação e o plano de
  validação; e mais o que não espera e as fechadas que cada uma toca.
  [As outras](#as-outras) têm uma entrada curta: o problema, as
  alternativas, a recomendação provisória e o que destrava — e as do lote
  rápido, também os riscos, o impacto e o plano.
- [As que o coordenador executa](#as-que-o-coordenador-executa) são as
  [B]: o coordenador as classificou assim (5.8), e elas não esperam o
  dono. Cada uma diz o que se faz e o estado; não contam no índice nem na
  ordem.
- [As fechadas](#as-fechadas-que-não-se-reabrem) são o que não se propõe
  de novo.
- Os ids do projeto ficam (DT-1, B5-1, A1-4); os novos dizem a fase do
  roteiro (`R12-`, `R13-`, `R15-`) ou o assunto. Uma alternativa que não
  sai das fontes, nem decorre direto das invariantes, leva **(minha)**: é
  deste dossiê, e vale como sugestão, não como desenho.
- Os ids que o dono já viu no relatório da entrega da continuidade da fase
  15 — a DE-1, o DN-4, a DH-1, a DH-2, a DH-3, a DC-1′ e a DX-1 — vêm ao
  lado dos deste dossiê, com as recomendações dadas lá; e os da pendência
  #298 — o A3, o A5, o F4, o F6 e o I7 —, nas entradas em que cabem.
- As fontes são as do commit `7564758`, de 17/11/2026 — as linhas citadas
  do código e do README, na forma `arquivo:linha`, são as dele —, mais o
  relatório da continuidade e a pendência #298, do coordenador. Se uma
  fonte mudar, ela vale. Quando o dono decidir, a entrada passa às
  fechadas, com a data e a alternativa, e o README — as [Decisões
  pendentes](../README.md#decisões-pendentes) e o
  [Roteiro](../README.md#roteiro) — se acerta.

## O índice

Só as decisões do dono, na ordem recomendada. As [B] — a A1-4, a F4, a
I7, a A9-RESUMO, o DN-4, a SDK-CANAL (DC-1′) e a R12-IC-NOS — estão em
[As que o coordenador executa](#as-que-o-coordenador-executa), e não
contam aqui. Entre parênteses, o id que o dono já viu no relatório da
continuidade.

| Id | Decisão | Área de 5.3 | Destrava | Exposição de hoje | Fonte |
|---|---|---|---|---|---|
| [M-EXEC](#m-exec) (DE-1) | O `exec` e a malha do processo, com a F6 | identidade de programa e proveniência | o handoff (fraco); um limite do SDK | baixa: enquanto a imagem nova exerceria `fabric.offer` sobre a intenção, a descoberta mostra o endpoint com o programa que não roda mais; e a imagem nova lê e cancela as entregas da anterior, e vê os fluxos dela | [README](../README.md#decisões-pendentes) |
| [DT-1](#dt-1) | O Terminal, o servidor de janelas e o teclado da Pessoa, com o A3 e o A5 | identidade e confiança; o Gate e a Policy (quem escuta os nomes do sistema) | em parte, o consentimento (fase 13) e o aceite do handoff (DH-2); os resíduos do passo 1, do ξ e do ο | **real**: outro principal toma o foco, ou o nome `terminal` ou `janelas`, ou abre uma janela logo antes de a Pessoa digitar, e recebe o que ela digita — a senha também —, sem registro | [README](../README.md#decisões-pendentes) |
| [COTA-SOMA](#cota-soma) | A soma das cotas de processos e a cota por sessão | semântica de operação (a cota e a alocação) | a operação sob carga (fase 14); mais sessões e dispositivos (fase 15) | **real**, pela leitura: a pessoa que entra muitas vezes, em qualquer máquina; a mesma chave nas 8 sessões, com muitos núcleos ou com a máquina em uso; ou alguns titulares juntos — enchem a tabela de fios, e nada nasce, nem o Terminal — o `system.reboot` já não depende dela: o fio `energia` nasce no boot (a correção (1)) | [README](../README.md#decisões-pendentes) |
| [R15-HANDOFF](#r15-handoff) (DH-1 a DH-3) | O handoff, o próximo marco da fase 15: o que é, quem recebe, para onde | identidade e autoridade entre dispositivos | a linha em curso, a fase 15; a continuidade | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R13-BOOT](#r13-boot) | A cadeia de boot confiável | custódia (a política dos selos, na (b)); confiança (uma raiz nova, na (a) e na (c)) | a fase 13; a base de R12-IC-TPM e R12-IC-VALOR; e o caminho do Secure Boot que a fase 14 deixou de fora — a recomendação o deixa para depois, como opção do operador | **real, com a máquina na mão**: o disco e a máquina juntos abrem o selo da identidade, e o disco e o mesmo TPM satisfazem a política das chaves; o firmware não confere o iniciador | [Roteiro](../README.md#roteiro), fase 13 |
| [AUD-ANEL](#aud-anel) | Os registros do boot que saem do anel antes do journal | auditoria (uma lacuna nova) | — | baixa: hoje o boot faz poucos registros antes do journal | [PERSISTENCIA](PERSISTENCIA.md#a-reconstrução-da-auditoria-no-boot-b4) |
| [P-HISTORIA](#p-historia) | A história da autoridade que cresce sem fim | persistência (o formato da base) | — | baixa: depois de dezenas de milhares de operações, a persistência para, fechada | [PERSISTENCIA](PERSISTENCIA.md#como-ficou-76) |
| [AUD-JUNTO](#aud-junto) | A decisão de uma mudança no mesmo registro do journal que ela, ou antes | persistência e auditoria (a garantia escrita) | — | baixa: uma queda entre os dois registros deixa no disco a decisão sem a mudança; e a decisão que sai do anel na janela, com a lacuna gravada antes por outro, deixa a mudança no disco só com a lacuna antes dela | [PERSISTENCIA](PERSISTENCIA.md#a-auditoria-no-journal), [README](../README.md#testes) |
| [AUD-FALHA](#aud-falha) | A morte de um processo por uma falha, na auditoria | auditoria (um registro novo) | um sinal para o NSF | baixa: o NSF não vê um processo que sonda o kernel por falhas — o log e a contabilidade das falhas, sim | [README](../README.md#decisões-pendentes) |
| [R13-CONSENT](#r13-consent) | O consentimento — a Pessoa perguntada, e o registro que ela lê | Policy e autorização; quem lê a auditoria | o título da fase 13 | baixa: um agente edita o campo que a Pessoa largou, sem perguntar; ela não lê o registro | [Roteiro](../README.md#roteiro), fase 13 |
| [ALC-TEMP](#alc-temp) (DX-1) | A expansão temporária de alcance, por titular | Policy; autoridade dada por tempo | parte do consentimento | indireta: o acesso de uma hora vira linha da política até alguém tirá-la | [USABILIDADE](USABILIDADE.md#decisões-novas--para-quem-decide) |
| [R13-DESFAZER](#r13-desfazer) | O desfazer | persistência e auditoria | fecha a fase 13 | nenhuma nova | [Roteiro](../README.md#roteiro), fase 13 |
| [R12-SIMD](#r12-simd) | O SIMD nos processos | semântica de operação (o contrato dos registradores) | as otimizações de cifra (fase 12) | nenhuma: o custo da cifra em software | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-mTLS](#r12-mtls) | O certificado do cliente no TLS | criptografia e custódia (um domínio de assinatura novo) | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-PROXY](#r12-proxy) | O *proxy* | o Gate (um destino que ele não vê) | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12 |
| [R12-QUIC](#r12-quic) | O HTTP/3 e o QUIC — a avaliação recomenda adiar; o caminho pede o relógio | o Gate e a autorização (o relógio); semântica de segurança nova (o 0-RTT) | a infraestrutura da fase 12 | nenhuma | [Roteiro](../README.md#roteiro), fase 12; [QUIC](QUIC.md) |
| [R12-IC-TPM](#r12-ic-tpm) | A chave de assinatura dentro do TPM | custódia | a fase 12 (Web3) | a privada vive na memória do kernel; só a semente está selada | [ICP](ICP.md#o-que-não-existe-ainda) |
| [R12-IC-VALOR](#r12-ic-valor) | A rede principal com valor e com canister | custódia; operação irreversível (5.6) | a fase 12 (Web3) | nenhuma: a política padrão não alcança a rede principal | [ICP](ICP.md#na-rede-principal) |
| [R12-IC-OUTROS](#r12-ic-outros) | O resto do IC | conforme o item | — | nenhuma | [ICP](ICP.md#o-que-não-existe-ainda) |
| [R15-REMOTOS](#r15-remotos) | Os recursos remotos | identidade e autoridade entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-PRESENCA](#r15-presenca) | A presença | identidade e confiança entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-CONTINUIDADE](#r15-continuidade) | A continuidade | semântica de operação entre dispositivos | a fase 15 | nenhuma | [Roteiro](../README.md#roteiro), fase 15 |
| [R15-PACOTES](#r15-pacotes) | Os pacotes | confiança (editores, versões, revogação de selo) | a fase 15 | nenhuma | [SDK](SDK.md#o-que-não-existe) |
| [B5-1](#b5-1) | Restaurar num volume recusado | persistência (a âncora) | o grupo B da fase 14 | operação: o volume recusado não volta | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-2](#b5-2) | Recuperar depois de perder o disco | custódia e confiança | o grupo B da fase 14 | operação: as cópias de um disco perdido não abrem | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-3](#b5-3) | Restaurar noutra máquina, ou migrar | identidade e confiança entre máquinas | o grupo B da fase 14 | operação: uma cópia não sai da máquina | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |
| [B5-4](#b5-4) | Restaurar o estado de autoridade | persistência (R1, R6) | o grupo B da fase 14 | operação: o estado de autoridade não está na cópia | [OPERACAO](OPERACAO.md#o-que-o-duke-ainda-não-faz-grupo-b) |

## A ordem recomendada

A DE-1 vem antes de tudo: é pequena, o dono já a viu apresentada assim —
"decidir primeiro" —, e decidi-la não atrasa nenhuma outra. Depois, três
critérios, nesta ordem: a exposição real que se alcança sem a máquina na
mão; o que destrava a linha em curso, a fase 15; e então a exposição com
a máquina na mão e o resto do roteiro. E uma regra: o que depende de
outra decisão vem depois dela. As [B] não entram na ordem: o coordenador
as executa pelo roteiro ([As que o coordenador
executa](#as-que-o-coordenador-executa)).

1. **M-EXEC (DE-1)**, com a **F6** dentro — pequena, e sobre o `exec`; a
   F4, do mesmo `exec`, é [B]. A DE-1 destrava, fraco, o handoff.
2. **DT-1** — a maior exposição real que espera uma decisão: a credencial
   da Pessoa capturada por outro principal, sem registro. E é a base do
   consentimento e do aceite do handoff (a DH-2, "aceite só pela entrada
   dela") — em parte: a recomendação fecha o nome e o foco tomados, a
   janela de outro principal que abre logo antes de uma pergunta e, para
   quem aperta a sequência de atenção, a que imita o console; mas o aceite
   e a confirmação não são linhas de credencial, e uma janela que os imita
   a DT-1 não impede — a DH-2 e o R13-CONSENT decidem isso.
3. **COTA-SOMA** — a outra exposição real: a pessoa que entra muitas
   vezes, a mesma chave em várias sessões, ou alguns titulares juntos
   param a criação de fios da máquina. A decisão é estreita, e as
   correções [B] em volta não esperam.
4. **R15-HANDOFF — a DH-1, a DH-2 e a DH-3** — o próximo marco da linha em
   curso — o roteiro já o põe primeiro, e por isso o DN-4 é [B] —, com as
   recomendações que o dono já viu. Depende da DE-1 (fraco) e da DT-1, e
   bloqueia a continuidade.
5. **R13-BOOT** — fecha, na máquina de referência com o PTT, a exposição
   de quem tem a máquina na mão; com um TPM discreto, fica o barramento. É
   o incremento seguinte da fase 13, e a base de custódia que R12-IC-TPM e
   R12-IC-VALOR pedem. Abre o caminho do Secure Boot que a fase 14 deixou
   de fora, mas a recomendação o deixa para depois, como opção do
   operador.
6. **AUD-ANEL, P-HISTORIA, AUD-JUNTO e AUD-FALHA** — o lote rápido:
   exposição baixa, poucas alternativas cada, e recomendações pequenas —
   as duas primeiras, esperar medindo; a AUD-JUNTO, o padrão que o armazém
   já usa; a AUD-FALHA, deixar como está até o NSF pedir o sinal —; com os
   riscos, o impacto e o plano já escritos, decididas de uma vez.
7. **R13-CONSENT**, com a **ALC-TEMP (DX-1)** — o título da fase 13;
   depende da DT-1. A DX-1 espera um consumidor: o consentimento é ele.
8. **R13-DESFAZER** — fecha a fase 13; depende do R13-CONSENT.
9. **R12-SIMD, R12-mTLS e R12-PROXY** — fecham os incrementos de
   infraestrutura da fase 12. Antes do mTLS, o roteiro põe a gestão de
   certificados — "o NTP, a gestão de certificados e o mTLS, nessa ordem"
   (README.md:12706-12707) —, que não está nem entre os feitos nem entre
   os que pedem uma decisão (README.md:12732-12734): conferir o estado
   dela antes da R12-mTLS; se pedir uma decisão, ela entra no índice.
   **R12-QUIC**: a avaliação está feita ([QUIC](QUIC.md)) e recomenda
   adiar — sem consumidor, não há o que decidir agora.
10. **R12-IC-TPM e R12-IC-VALOR**, depois da R13-BOOT; **R12-IC-OUTROS**
    quando houver a necessidade.
11. **Os outros marcos da fase 15**, na ordem do roteiro — R15-REMOTOS,
    R15-PRESENCA, R15-CONTINUIDADE e R15-PACOTES —, a continuidade depois
    do handoff. Cada um pede antes um desenho com as decisões dele, como o
    DN-1, o DN-2, o DN-3 e o handoff pediram.
12. **B5-1 a B5-4** — o B5-1 é o único que não esbarra numa fechada; os
    outros três esbarram no B2, na invariante da identidade, ou na R1 e na
    R6.

## As propostas completas

### M-EXEC

**O `exec` e a malha do processo** — a **DE-1** do relatório da
continuidade da fase 15, com a **F6** dentro (um achado do adversário do
AE-1, na pendência #298). A [F4](#f4), do mesmo adversário e sobre o mesmo
`exec`, é [B]: está em [As que o coordenador
executa](#as-que-o-coordenador-executa).

**O problema.** Na troca de imagem, os endpoints do processo continuam
abertos com a identidade do programa que os ofereceu — o nome, o resumo e
o editor da imagem anterior, que a descoberta mostra —; o que esperava
neles passa à imagem nova, que também continua com a janela de nonces do
processo. Cada operação da imagem nova passa pelo gate com o manifesto
dela, no mesmo titular: nenhuma autoridade a mais. Mas a identidade do
endpoint deixa de ser a do programa que roda — e a malha existe para que
quem procura escolha pelo que o programa **é**.

E o que a imagem anterior **mandou** também passa à nova. O
`fabric.status` e o `fabric.cancel` acham a entrega pelo canal de quem
manda — o processo (`kernel/src/malha.rs:892-899` e `:936-957`;
`politica/src/malha.rs:678-754`) —, e o `exec` não muda o canal
(`kernel/src/usuario/mod.rs:1591-1602`): a imagem nova lê o estado e a
resposta — até 512 bytes — das entregas da anterior, e cancela as que
ainda esperam. Zerar a janela de nonces não muda isso: a entrega se acha
pelo canal, e não pelo nonce. As conexões de rede também são do processo
(`kernel/src/rede/conexoes.rs:56-66`) e passam à imagem nova — mas cada
uso delas passa pelo gate com o manifesto novo, e isso fica como está.

E a F6: pelo `stream.status`, a imagem nova vê os fluxos da anterior. Dos
que o `exec` acabou (`o programa mudou`), a lápide — o estado, o motivo do
fim e os bytes de cada sentido —; e, dos que a anterior tinha fechado e a
outra ponta ainda lê, também a outra ponta
(`politica/src/fluxo.rs:549-556` e `:1253-1301`).

**A exposição de hoje.** Baixa. A descoberta só mostra o endpoint — com o
nome, o resumo e o editor da imagem anterior — enquanto a imagem nova
exerceria `fabric.offer` sobre a intenção, pelo manifesto e pelo editor
dela ([MALHA](MALHA.md#o-caminho-de-um-pedido), "O destino ainda
recebe?", MALHA.md:103-107; `kernel/src/autorizacao.rs:3505-3541`;
`kernel/src/fios/mod.rs:3104-3113`): o que se atribui errado é qual de
dois programas, os dois com a intenção, atende. E o programa novo, no
mesmo titular, lê e cancela as entregas do anterior e vê os fluxos dele.

**As evidências.** [MALHA, A identidade de um
programa](MALHA.md#a-identidade-de-um-programa) e [Revogação e
fim](MALHA.md#revogação-e-fim); [SDK, O canal cheio, a morte, a troca de
imagem](SDK.md#o-canal-cheio-a-morte-a-troca-de-imagem) — as designações e
os avisos na fila saem no `exec` (NS17, NS36), e os endpoints ficam —, e
[SDK, Limites conhecidos](SDK.md#limites-conhecidos); o precedente do
[FLUXOS, Os estados](FLUXOS.md#os-estados): a ponta de um fluxo é do
processo e não sobrevive ao `exec` (`o programa mudou`), encerrada dentro
da ordem das gravações, logo depois do ponto sem volta — o trabalho do
AE-1; o caso `malha: o impostor nao alcanca o que e do outro`; e o
`stream.status`, que diz "o estado, o motivo do fim, os bytes de cada
sentido e a outra ponta" ([FLUXOS, Os comandos](FLUXOS.md#os-comandos)).

**As alternativas.** As duas primeiras são as do README.

- (a) Fechar os endpoints no `exec`, como no fim do processo: o que
  esperava neles é anulado (`voided`), e o fecho vai à auditoria com o
  motivo. Com ela, a F6: o fluxo da imagem anterior deixa de ser da nova.
  E, **(minha)**, para ser de fato "como o fim do processo": o que a
  anterior mandou continua — como continua o que manda um processo que
  acaba —, mas a imagem nova não o alcança; o `fabric.status` e o
  `fabric.cancel` dela não acham as entregas da anterior.
- (b) Mudar a identidade deles para a da imagem nova: a descoberta passa a
  mostrar o programa que roda.
- (c) Como hoje, documentado.

**Os riscos.**

- (a): o programa que se troca por outro — ou por si mesmo — perde os
  endpoints e oferece de novo; quem mandou vê `voided`, e manda de novo.
  Com a janela de nonces zerada, a imagem nova pode mandar o que a
  anterior mandou, com o mesmo nonce, e cria outra entrega — em nome dela,
  que é o certo. As entregas da anterior ficam sem quem as consulte ou
  cancele, como as de um processo que acabou.
- (b): quem escolheu pelo resumo antes da troca fala com outro programa
  sem saber; o registro da oferta diz um programa, e o endpoint outro — a
  cadeia de ids da auditoria precisa de um elo novo.
- (c): a atribuição errada continua, e cresce na fase 15, com um endpoint
  visto de outro Duke.

**O impacto.** `kernel/src/malha.rs` e o caminho do `exec` em
`kernel/src/usuario`, que já encerra ali os fluxos da ponta; a janela de
nonces do processo; a entrega resolvida por uma marca da troca, e não
pelo programa — que, numa troca para si mesmo, é o mesmo: o mesmo nome,
resumo e editor (`politica/src/malha.rs:134-139`) —, nem só pelo canal,
no `fabric.status` e no `fabric.cancel`; o fluxo resolvido do mesmo jeito
no `stream.status` (a F6); o registro `fabric.withdraw` com o
motivo; o SDK e a MALHA na documentação. As conexões de rede não mudam.

**A recomendação.** A dada no relatório da continuidade: **o `exec` fecha
os endpoints do processo e o que espera neles, e zera as janelas de
nonces — como o fim do processo —, dentro da v2**; e, com ela, a F6. É
pequena, e bloqueia — fraco — o handoff: **decidir primeiro**. É a (a): o
mesmo ciclo de vida da ponta de um fluxo — um objeto da malha é do
processo **e** da imagem que o criou, e uma troca para o mesmo programa
também é outra imagem —, e a identidade de um endpoint volta a ser sempre
a do programa que roda. A janela zerada é o que separa as entregas das
duas imagens: com a de antes, um nonce da imagem nova,
com o conteúdo de uma entrega da anterior, devolveria o id dela — "o
mesmo nonce com o mesmo conteúdo é o reenvio" —, a mesma confusão de
proveniência. Mas a janela não cobre o que a anterior mandou — a entrega
se acha pelo canal —: a recomendação do relatório não o diz, e este
dossiê acrescenta a parte da (a) que o diz. "Dentro da v2": muda o
comportamento, e nenhum nome do contrato — ver o DS-2, abaixo.

**O plano de validação.** Um caso: o programa oferece, recebe uma entrega
pendente e troca de imagem; o endpoint some da descoberta, a entrega fica
`voided`, o fecho vai à auditoria com o motivo, e a imagem nova oferece de
novo e recebe; o nonce que a anterior usou não devolve o id da entrega
dela; o `fabric.status` e o `fabric.cancel` de uma entrega da anterior
respondem à nova como para uma entrega que não existe, e a entrega segue
para o destino; e o `stream.status` de um fluxo da anterior — a lápide, e
o fechado que a outra ponta ainda lê — responde do mesmo jeito. E o mesmo
caso com a troca para o mesmo programa — o mesmo nome, resumo e editor —,
que só a marca da troca separa. As mutações — o endpoint que sobrevive ao
`exec`, a janela que não zera, a entrega da anterior alcançável pela nova,
o fluxo da anterior visível, a entrega resolvida pelo programa e não pela
marca da troca —, uma de cada vez, reprovam. As duas arquiteturas; a
bancada `cargo xtask sdk`, que não deve mudar.

**O que não espera.** Conferir quais programas da imagem oferecem um
endpoint e trocam de imagem: os dados da decisão.

**As fechadas que ela toca.** A DF-1 — o fluxo é um objeto da malha,
entre dois processos do titular. O DS-1 — o aviso só sinaliza: a troca
larga as designações antes do resto, como hoje. O DS-2: o SDK diz que "os
endpoints persistem, como sempre persistiram" na troca de imagem
(SDK.md:320-326), e o contrato manda que "um nome nunca muda de sentido"
(SDK.md:74-76); fechar os endpoints e tirar da imagem nova o que a
anterior mandou e os fluxos dela muda o que o contrato descreve, e a
decisão é também dizer que isso cabe "dentro da v2". E "o processo como
endpoint" (1.7): os objetos da malha continuam do processo — "É do
processo: só ele o abre, lê o que chega por ele, confirma e o fecha, e ele
some com o processo" (MALHA.md:33-35) —; a (a) acrescenta que acabam
também quando a imagem dele muda.

### DT-1

**O Terminal, o servidor de janelas e o teclado da Pessoa.** Inclui o A3
(o ritmo da senha nos contadores) e o A5 (o registro por tecla com o foco
tomado) da pendência #298 — achados do adversário do passo 1 da
continuidade —, e o A4 (a senha no lugar errado). Os rótulos DT-1a a
DT-1e são os das mensagens de commit; o README usa só "DT-1a". Para
conferir cada id antigo: `008faef` (DT-1b, N2a); `dc6a96b` e `d5b4755`
(DT-1c); `4f192e6` (DT-1a, DT-1d); `d0025b0` (DT-1e); `5a9bf69` (o O6 do
ο); `31af5b3` (o X2 e o X3 do ξ); `2b83752` (o A3 e o A4). O "A3" de
`docs/FLUXOS.md` — a espera da ordem das gravações sem fila — é outro
achado, de outra rodada.

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
  (DT-1b; o N2a). Sem ninguém entrado no console físico, a tecla de uma
  janela que não é de Terminal não chega a ela: é recusada, e cada uma
  vira um registro `keyboard` `DENY_NOT_AUTHENTICATED` na auditoria — com
  o foco tomado no login, a conta e o ritmo da senha (o A5). E o `press` de
  um agente na caixa de fechar do Terminal fecha o console e encerra a
  sessão da Pessoa que está nele — gravado, e não recusado (DT-1e; o X2 do
  adversário ξ).
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
  publica no canal `terminal`, ou no `janelas`; `kernel/src/interpretador.rs`
  — `tratar_tecla_de_janela`, que grava o `keyboard` recusado, tecla a
  tecla (o A5).
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
- Da pendência #298, o A3 e o A5 estão acima, com as opções que ela dá —
  abaixo, na 3(c) e na 2(e). O F4 e o F6, do adversário do AE-1, ficam com
  o `exec`: o F4 é [B] ([F4](#f4)), e o F6 vai na [M-EXEC](#m-exec).

**As alternativas**, por pergunta:

1. **O Terminal e o servidor.**
   - (a) **(minha)** Os nomes `terminal` e `janelas` reservados ao
     Terminal e ao servidor de janelas, reconhecidos pela identidade de
     programa que o kernel carregou — o nome do manifesto, o resumo da
     imagem, sem editor de fora ([MALHA, A identidade de um
     programa](MALHA.md#a-identidade-de-um-programa)) — e pelo titular
     `sistema`. O `escutar` de outro nesses nomes é recusado, e gravado;
     quem escreve no pseudo-terminal sem a marca passa a ser só o Terminal
     reconhecido. É um mecanismo: uma regra do kernel sobre quem escuta um
     nome, fora do gate e da política — como a regra da linha da pessoa,
     em que "a decisão do `ui.act` continua a do gate, gravada; a recusa é
     da linha" (README.md:8369-8370) —, e por isso toca duas invariantes
     de 1.7: "toda operação passa pelo Gate" e "a Policy como fonte da
     decisão".
   - (b) **(minha)** Uma permissão nova do vocabulário fechado para
     escutar um nome do sistema, decidida pelo gate — como o
     `terminal.attach` já é para o pseudo-terminal
     (`kernel/src/usuario/mod.rs:895-907`). É autorização: a reserva passa
     pelo gate e pela política, que a enumera papel a papel.
   - (c) **(minha)** Como hoje, com a captura gravada: o `escutar` num
     nome do sistema e o foco tomado vão à auditoria. Só detecção.
2. **O foco.**
   - (a) **(minha, pelo uso de hoje)** O foco muda só pelo clique da
     Pessoa e para a superfície que acaba de abrir, uma vez — dois dos três
     usos que existem: "o kernel passou a dar o foco no aperto do botão", e
     "o servidor agora só pede o foco para a janela que acabou de abrir". O
     terceiro é o Terminal que vem para a frente, com o foco, quando a barra
     o chama — o `ABRIR`, que o leva a `vir_para_a_frente`
     (`programas/src/bin/terminal.rs:390` e `:273-279`), pelo botão da
     barra, pela F3 ou pelo `press` de um agente —; a 2(a) o tira (ver o
     risco dela, e a 2(f)).
   - (b) **(minha)** O foco não sai de um console enquanto a linha dele
     pede uma credencial — o nome, as senhas, a cerimônia.
   - (c) O servidor reconhecido decide o foco de todas as janelas — o
     desenho do servidor no README, "o servidor decide janelas, decoração,
     foco e roteamento" —; o pedido de outro dono vira pedido a ele.
   - (d) **(minha)** Uma sequência de atenção segura: uma tecla que só o
     kernel trata e que leva a Pessoa ao console de verdade — a prática do
     Ctrl+Alt+Del —; e, enquanto o console está por cima depois dela,
     nenhuma janela ganha o foco ao abrir.
   - (e) O A5, pelas opções da pendência: dobrado na DT-1b — com o foco
     que não sai da linha do login (2b), a tecla vai ao console, e não
     vira registro, quando o foco está no console ao começar o login —;
     ou, parcial, um limitador de ritmo dos registros `keyboard`
     recusados.
   - (f) **(sugestão do revisor, para o dono considerar)** O foco na
     abertura — a segunda metade da 2(a) — só para quem tem a permissão da
     1(b): a janela de outro principal só ganha o foco pelo clique da
     Pessoa. E, **(minha)**, o pedido de quem tem a permissão da 1(b) fora
     da abertura vale quando a barra o chamou pela Pessoa — o botão ou a
     F3 —, uma vez: o Terminal que a barra chama vem para a frente com o
     foco, e o `press` de um agente o traz sem ele.
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
   - (c) Os contadores — o A3 —, pelas opções da pendência: manter, e
     documentado; agregar ou omitir — os `scheduled` dos fios do Terminal
     e do servidor e a linha do teclado em `irq.stats` somados por janela
     de tempo, ou fora dos relatórios —; restringi-los ao `sistema`; ou
     dobrá-los na DT-1c, com a versão do campo e o `revision`. O README:
     "muda o que esses relatórios prometem, ou a quem".
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
  programa que hoje o pede a qualquer hora deixa de recebê-lo. E tira o
  terceiro uso: o Terminal que a barra chama vem para a frente sem o
  foco, e a Pessoa clica justamente na janela em que digita credenciais —
  e o clique é o caminho da janela que imita —, a menos que a 2(f) valha
  também para ele, como a parte minha dela propõe.
- 2(b) é uma regra nova no roteamento da tecla, e só segura o foco
  depois que a linha pede a credencial: uma janela falsa aberta antes da
  linha da senha ainda engana a Pessoa — mesmo com a 1(a) ou a 1(b): a
  reserva dos nomes não impede uma janela que se passa pelo Terminal, e a
  2(a) dá o foco à que acaba de abrir. Só a 2(d) fecha as duas, para quem
  a aperta, segurando o foco no console (ou com a 2(f)).
- 2(c) põe um protocolo novo entre cada programa e o servidor: o foco de
  uma superfície que não é dele.
- 2(d): a tecla já chega ao kernel pelos três caminhos — o PS/2, o
  `virtio-input` e o USB entregam a `teclado::evento`
  (`kernel/src/teclado.rs:310`) —, e as teclas de função já vão ao
  console com o foco numa janela (o roteamento: `:322-328`, antes da
  conferência do foco, em `:342-348`), onde passam pelo gate como
  `ui.act`, com a sessão do console, e são recusadas sem ninguém entrado
  (`kernel/src/interpretador.rs:936-946` e `:1180-1194`). A sequência age
  antes do login e fora do gate, como o clique fora das janelas, que já
  devolve o foco ao kernel (`kernel/src/ponteiro.rs:173-184`): é esse o
  precedente dela. O custo é o console de verdade mostrado por cima de
  qualquer janela, uma tela que o kernel desenha, e o foco seguro nele
  enquanto ele está por cima — senão, sem a 2(f), quem perdeu o foco é
  avisado (`FOCO_PERDIDO`, `kernel/src/superficies.rs:601-627`) e abre
  outra janela na hora, que o toma antes do "senha⏎", com a linha que
  ainda não pede credencial. E ela só protege quem a aperta antes de
  digitar: é um hábito. **(minha)** Exigi-la antes
  de cada credencial, como o "Ctrl+Alt+Del para entrar", tira o hábito do
  caminho, mas muda o login de todo console e as bancadas com a pessoa no
  teclado.
- 2(e): o limitador de ritmo só espaça os registros — a conta, e parte do
  ritmo, continuam na auditoria.
- 2(f): os programas que pedem o foco ao abrir a janela — o `conversa` e o
  `formulario` (`programas/src/bin/conversa.rs:318`,
  `programas/src/bin/formulario.rs:111`) — deixam de recebê-lo, e a
  Pessoa clica; e a permissão da 1(b) passa a valer duas coisas: escutar
  um nome do sistema e ganhar o foco ao abrir. O foco na abertura passa a
  ser decidido pelo gate, e cada janela que abre com o foco vira uma
  decisão gravada — "toda decisão é gravada" (README.md:5040). Fecha a
  janela de outro principal que abre logo antes de uma pergunta, e não a
  que imita: nesta, a Pessoa ainda clica. A parte minha — o Terminal que a
  barra chama pela Pessoa — pede que o kernel saiba quem apertou a barra,
  e tira do `press` de um agente o poder, que ele tem hoje, de levar o
  teclado da Pessoa ao Terminal dela.
- 3(a) muda a coordenação: a Pessoa passa a ter prioridade sobre o agente
  nas linhas de credencial. No resto, a regra fica.
- 3(c): agregar ou omitir muda o que o `observador` lê, e os casos e as
  bancadas que contam o `scheduled` e o `irq.stats` mudam junto;
  restringir ao `sistema` tira dele o relatório inteiro.
- 3(d) abre uma exceção na regra da coordenação — a versão "só sobe com
  uma mudança que valeu" (README.md:8672-8673) —: numa linha de
  credencial, a tecla muda o campo e a versão só sobe no Enter. Os
  agentes já não editam essas linhas, e a exceção vale só nelas.

**O impacto.** O kernel: `eventos.rs` (os nomes), `superficies.rs` (o
foco; na 2(f), o foco na abertura decidido pelo gate; na 2(d), o foco
seguro no console), `barra.rs` (na parte minha da 2(f), quem apertou),
`teclado.rs` (o histórico; na 2(d), a sequência, tratada antes do foco),
`interpretador.rs` e `coordenacao.rs` (as linhas e o arrendamento),
`ui.rs` e, na 2(d), o console por cima das janelas, e os relatórios em
`agent/commands.rs`; os programas `terminal` e `janelas`, e, na 2(f), os
que pedem o foco ao abrir; a política, na 1(b) e na 2(f); o
`cargo xtask invariantes`, os nomes reservados; e a
documentação dos [Consoles](../README.md#consoles), da
[Coordenação](../README.md#coordenação), de [Operar por uma
pessoa](../README.md#operar-por-uma-pessoa), do
[OPERACAO](OPERACAO.md#a-própria-senha) e do
[PAREAMENTO](PAREAMENTO.md#os-comandos). Uma recusa nova do `escutar` num
nome reservado é comportamento, e não um nome do contrato v2: conferir
contra a regra do DS-2 ([SDK, O contrato v2](SDK.md#o-contrato-v2-ds-2)).

**A recomendação.** Aprovar um princípio — **o caminho da Pessoa** —, de
que os itens da DT-1 saem como [B]. O dono decide parte a parte; cada uma
fecha o que a tabela diz, e só isso:

| O caminho de captura | O que o fecha |
|---|---|
| o nome `terminal` ou `janelas` tomado por outro principal, que recebe o `ABRIR` da barra | a 1(a) ou a 1(b) |
| o foco pedido a qualquer hora — `controlar` com `FOCO` —, também no meio de uma credencial (a DT-1b, o N2a) | a 2(a) com a 2(b) |
| a janela que abre logo antes de uma pergunta à Pessoa e ganha o foco na abertura. Com alguém entrado no console físico, a tecla vai a ela (`kernel/src/interpretador.rs:1069-1080`): o "senha⏎" que a Pessoa digita para o console, e a senha atual depois. Sem ninguém entrado, com o foco nela ao começar o login, as teclas do login, um registro cada uma (o A5) | a 2(f), para a janela de outro principal; a 2(d), para quem a aperta, segurando o foco no console (ou com a 2(f)) |
| a janela que se passa pelo Terminal, pela linha do login ou por uma pergunta, sem escutar nome nenhum: a Pessoa clica nela, e ela ganha o foco pelo clique | só a 2(d), para quem a aperta, segurando o foco no console (ou com a 2(f)) |
| o agente nas linhas de credencial — o `ui.claim`, o `press` na caixa de fechar (a DT-1d, a DT-1e) | a 3(a) |
| o histórico do teclado com a senha digitada adiantado num Terminal (a DT-1c, o X3) | a 3(a) |
| o rastro da tecla — a versão, o prazo e o `revision` (a DT-1c); os contadores (o A3) | a 3(d) e a 3(c) |

Nenhuma delas faz do aceite do handoff (a DH-2) ou da confirmação do
consentimento (o R13-CONSENT) uma pergunta que nenhum processo imita: eles
não são linhas de credencial — a 2(b) e a 3(a) não os cobrem —, e o
aceite da DH-2(a) é pedido por um programa, numa janela. A 2(f) tira
deles a janela de outro principal que toma o foco ao abrir — e tira do
próprio pedido o foco na abertura, para que ele não o tome enquanto a
Pessoa digita noutra janela —; a imitação continua. Só uma pergunta feita
no console de verdade, depois da sequência da 2(d), não se imita, e ela
pede ao kernel o que a DH-2(a) não pede: isso é da DH-2 e do R13-CONSENT
decidir.

Este dossiê recomenda:

1. **os nomes**: o Terminal e o servidor de janelas são os únicos que
   escutam `terminal` e `janelas`. O dono decide se a reserva é mecanismo
   — a 1(a), uma regra do kernel fora do gate — ou autorização — a 1(b),
   uma permissão que a política enumera. Este dossiê recomenda a
   **1(b)**: ela não abre exceção em "toda operação passa pelo Gate" nem
   em "a Policy como fonte da decisão", e segue o precedente do
   `terminal.attach`; o preço é uma permissão a mais no vocabulário. Pela
   1(b), a DT-1a e o O6 ficam com o `terminal.attach`: só quem a política e
   o manifesto deixam tem o pseudo-terminal — em 7564758, o `terminal`
   (`programas/src/bin/terminal.rs:70`) e o `pseudo` da suíte
   (`programas/src/bin/pseudo.rs:24`);
2. **o foco**: muda pelo clique da Pessoa e para a janela que acaba de
   abrir (2a) — na abertura, só a de quem tem a permissão da 1(b), e,
   fora dela, o Terminal que a barra chama pela Pessoa (2f, com a parte
   minha: senão o Terminal vem sem o foco, e a Pessoa o escolhe pelo
   clique, que é o caminho da janela que imita) —, e não sai de uma linha
   que pede credencial (2b): o que dobra o A5 quando o foco está no
   console ao começar o login (2e);
3. **a sequência de atenção, já** (2d), com o foco seguro no console
   enquanto ele está por cima: é a única que fecha a janela que imita, e a
   que leva a Pessoa ao console de verdade antes de uma credencial,
   qualquer que seja a janela com o foco. O custo é o console mostrado por
   cima das janelas: a tecla já chega ao kernel, e o clique fora das
   janelas já devolve o foco ao kernel, fora do gate — o precedente dela
   (ver os riscos);
4. **as linhas de credencial são da Pessoa** (3a): o `ui.claim` e o
   `press` de um agente nelas — e na caixa de fechar de um Terminal com
   alguém entrado — são recusados e gravados, e a tecla do Terminal é
   coordenada, e entra no histórico, onde o console a consome;
5. **o rastro**: a tecla de uma credencial não deixa rastro fora do
   console — nem na versão e no prazo do campo, nem no `revision` da
   árvore (3d) —, e os contadores do `system.read` deixam de andar tecla a
   tecla: agregados, somados por janela de tempo (3c).

**O que fica aberto, com a recomendação inteira:** quem digita uma
credencial numa janela que imita o console, sem apertar antes a
sequência — a 2(d) protege quem a aperta —; o aceite e a confirmação,
como acima; e, como resíduo aceito, a senha digitada no lugar errado (o
A4): numa linha de comando, nada distingue uma senha de um comando.

**Sem a 2(d) agora** — se o dono a deixar para depois —, fica também a
janela que abre logo antes de uma pergunta à Pessoa, ou que a imita;
fecha com a 2(d). Com a 2(f), a que abre logo antes só pode ser do
próprio `sistema`, e a que imita continua. **Sem a 2(f)**, a janela de
outro principal que abre logo antes de uma pergunta ganha o foco, e
recebe o que a Pessoa digita sem apertar antes a sequência — o caso mais
à mão: uma superfície invisível, aberta na hora certa —; e, se a 2(d) não
segurar o foco no console, também o que ela digita depois da sequência:
quem perdeu o foco é avisado (`FOCO_PERDIDO`) e abre outra na hora. E,
com a 2(a), o Terminal que a barra chama vem para a frente sem o foco.

**O plano de validação.**

- Um caso por caminho de captura — antes, para medir a exposição; depois,
  com a decisão: o processo de um agente que escuta `terminal` com o
  Terminal fechado; o que escuta `janelas` com o servidor fora; o dono de
  uma superfície invisível que pede o foco no meio da senha do login, da
  `senha` e da cerimônia; a janela de outro principal que abre logo antes
  do `senha⏎`, com a Pessoa entrada no console físico, e a que tem o foco
  quando o login começa, sem ninguém entrado; a janela que imita o
  Terminal, clicada, e a sequência que leva a Pessoa ao console de
  verdade, também com uma janela por cima, e com a que perdeu o foco
  abrindo outra na hora, ou em laço; o Terminal que a barra chama — pela
  Pessoa, com o foco; pelo `press` de um agente, sem ele —; a senha
  adiantada num Terminal; o `ui.claim` de um agente na linha do nome; o
  `press` dele na caixa de fechar com a Pessoa entrada; os contadores que
  o `observador` lê, com uma senha digitada.
- As bancadas com a pessoa no teclado — `cargo xtask senha` e a do
  pareamento —, nas duas arquiteturas, em depuração e em release.
- Uma mutação por regra, uma de cada vez e restaurada: o nome reservado
  aceito; o foco dado no meio da credencial; o foco na abertura dado a
  quem não tem a permissão; o foco dado ao Terminal pelo `press` de um
  agente na barra; a sequência que não devolve o foco ao console, ou que
  chega à janela; a sequência que deixa uma janela aberta depois dela
  tomar o foco; o histórico escrito na chegada; o
  `ui.claim` aceito; o `press` aceito; o contador por tecla; a versão que
  anda por tecla na linha de credencial.
- Um agente adversário com uma tarefa só: capturar a senha da Pessoa por
  qualquer caminho, também pela janela que abre antes e pela que imita
  ([1.5](../CLAUDE.md#15-segurança-o-agente-adversário)).
- A CI completa, verde no último commit.

**O que não espera.** Os casos que reproduzem cada caminho de captura —
também a janela que abre logo antes e a que imita —, sem mudar o
comportamento: são os dados da decisão.

**As fechadas que ela toca.** O B3: um evento de hardware não é
autoridade — a tecla é evento; quem age é a sessão. A sequência da 2(d)
também: leva a Pessoa ao console, fora do gate, como o clique fora das
janelas, e não autoriza nada. O B4: a troca da própria senha é do
console. E duas invariantes de 1.7, pela pergunta 1: "toda operação passa
pelo Gate" e "a Policy como fonte da decisão". A 1(a) é uma regra do
kernel sobre quem escuta um nome, fora do gate e da política; a 1(b) põe
a mesma reserva no gate — e, com a 2(f), também o foco na abertura. O
foco (2), menos a 2(f), segue regras que já existem fora do gate — "foco
≠ autoridade" — e diz para onde a tecla vai; e a 3(a) recusa, fora
do gate, o `ui.claim` e o `press` de um agente nessas linhas, como a
regra da linha da pessoa recusa a edição — uma restrição depois do gate,
e não uma autorização.

### COTA-SOMA

**A soma das cotas de processos e a cota por sessão** — o que a decisão
14.1 não fecha.

**O problema.** A tabela de fios é uma só, para os fios do kernel e os
processos de todos: 95 vagas (`MAX_FIOS`), 88 livres na suíte com 4
núcleos — o fio `energia`, que nasce no boot desde a correção (1), toma
uma. A cota de processos protege um titular dos outros — desde a 14.1
e a alternativa 1 do A1, os vivos, os que nascem, os zumbis e os mortos
ainda não recolhidos de um titular ocupam no máximo a cota dele —, mas não
protege a tabela:

- vários titulares, cada um dentro da cota, a enchem: onze de cota 8
  ocupam as 88 vagas, e numa máquina em uso, com os serviços e os
  programas do boot no ar, bastam menos;
- a cota é por sessão, e não por identidade: a mesma chave de agente nas 8
  sessões cifradas — as quatro portas do `virtio-console` e as quatro
  vagas do TCP — soma 8 cotas; e uma pessoa ganha uma cota nova a cada
  login, com os processos do login anterior ainda vivos
  (README.md:5414-5415).

Quanto disso uma identidade sozinha alcança depende dos núcleos. A cota
do `operador`, na imagem, é 8 (`politica/src/lib.rs:399`); a do
`administrador` não entra na conta: ele é um teto, que não se exerce
(`kernel/src/autorizacao.rs:1012-1020`). 8 sessões da mesma chave de
operador dão 64 vagas, e com 4 núcleos sobram 88 — a chave sozinha não
enche a tabela.
Cada núcleo ligado além do primeiro toma uma vaga para o ocioso dele, e
as 95 vagas descem até as 32 de trabalho com os 64 núcleos ligados
(README.md:8754-8759): numa máquina com muitos núcleos, ou em uso, a
mesma chave enche sozinha. E quem enche sozinho em qualquer máquina é a
pessoa que entra muitas vezes — uma cota nova a cada login.

Com a tabela cheia, não nasce fio nenhum, de ninguém: outro titular não
lança programa, o Terminal não abre, a cerimônia de pareamento não
começa. O `system.reboot` não depende mais dela: o fio `energia` nasce no
boot, parado, e o pedido só o acorda — a correção (1), no `ee4ea45`;
antes, ele falhava depois de o pedido ir ao journal.

**A exposição de hoje.** Real, pela leitura, sem reprodução:
disponibilidade. Uma pessoa que entra muitas vezes, em qualquer máquina;
uma chave de agente nas 8 sessões, numa máquina com muitos núcleos ou em
uso; ou alguns titulares juntos — param a criação de fios da máquina.
Volta pelo `process.terminate` — do `sistema`, ou do administrador com a
prova —, ou pelo corte de energia.

**As evidências.** [README, Decisões
pendentes](../README.md#decisões-pendentes) — o item e os dois antes dele;
[Coordenação](../README.md#coordenação) — "A cota de processos", "O zumbi
na cota" e "Os mortos na cota"; a medida da 14.1: com a cota em 2, o
`colhedor` e 88 zumbis tomaram as 89 vagas livres, e daí em diante não
nascia fio nenhum, nem o `energia` (antes da correção (1)); os casos `zumbis: o morto conta na cota
ate o recolhimento`, `zumbis: os fios do kernel nao contam na cota` e
`zumbis: a recusa grava os mortos acima da cota`; e [as mutações MC1 a
MC9](../README.md#as-mutações-da-conta-de-vagas-alternativa-1).

**As alternativas.** As três primeiras são as do README, e "a soma das
cotas de titulares diferentes nenhuma das três fecha sozinha":

- (a) contar a cota pela identidade — a chave do agente, a pessoa —, e não
  pela sessão: fecha a soma das sessões da mesma chave e a dos logins da
  mesma pessoa;
- (b) encerrar os processos com a sessão: fecha a dos logins. Vale para a
  pessoa: os programas de uma sessão de pessoa que acabou já não pedem
  nada — "os programas da pessoa que saiu não pedem mais nada"
  ([MALHA](MALHA.md#revogação-e-fim)) —, e hoje só ocupam a vaga. Para um
  agente, não: o processo que ele lançou continua o agente depois que a
  conexão cai — "a autoridade é da chave" (README.md:4472-4477; o caso
  `canal tcp: o processo sem a conexao e a revogacao`,
  `kernel/src/testes.rs:40318`) —, e o gate procura o papel pela chave
  (`kernel/src/autorizacao.rs:1480-1490` e `:3429-3473`);
- (c) reservar vagas aos fios do kernel — a alternativa (2) da decisão do
  A1, que segue aberta aqui: salva a cerimônia e o coletor — o `energia`
  já nasce no boot —, e não o programa de outro titular nem o Terminal,
  que é um processo;
- (d) **(minha)** uma reserva também para o titular `sistema` — o servidor
  de janelas e o Terminal —, além da dos fios do kernel;
- (e) aceitar, como está.

**Os riscos.**

- (a): quem usa várias sessões da mesma chave em paralelo passa a dividir
  uma cota; a pessoa no console físico e num Terminal também. A conta
  continua sob a trava do escalonador, no lugar da de hoje
  (`Escalonador::processos_de`).
- (b): muda o ciclo de vida do processo — o programa que a pessoa lançou
  morre no `logout`. Para um agente, mudaria o que a autoridade é: hoje o
  processo dele continua o agente sem a conexão; encerrá-lo com a sessão o
  prenderia à conexão viva — a mutação que o caso `canal tcp: o processo
  sem a conexao e a revogacao` reprova. Para um agente, a (b) não se aplica
  sem outra decisão.
- (c) e (d): menos vagas para os processos; o tamanho da reserva é uma
  escolha a medir.
- Nenhuma fecha a soma de titulares diferentes. Com (a) e (c), o resíduo é
  o de muitos titulares registrados, cada um dentro da cota — e o registro
  de cada um é uma operação administrativa com prova.

**O impacto.** `kernel/src/fios` (a conta e a reserva); o sentido da linha
`processos <papel> <n>` da política, sem mudar a gramática; a
documentação da Coordenação e das Decisões pendentes; os casos `zumbis:` e
`recolhimento:`; uma campanha de mutações.

**A recomendação.** (a) + (c). A (b), só para a pessoa, e só se a medida,
depois delas, mostrar processos de sessões acabadas segurando a cota de
quem entra de novo; a (d), se mostrar o Terminal sem vaga com (a) e (c).

**O plano de validação.** Primeiro, um caso que reproduz o esgotamento de
hoje — a pessoa que entra muitas vezes; a mesma chave nas 8 sessões, com
mais núcleos; vários titulares —, para medir.
Depois, o mesmo caso com a decisão: a reserva intacta, o `system.reboot`,
o Terminal e a cerimônia de pé. As rajadas de `fork` de várias sessões ao
mesmo tempo, nas duas arquiteturas. As mutações, uma de cada vez: a conta
por sessão de volta, a reserva ignorada, a reserva contada na cota. A CI
completa.

**O que não espera** — as correções [B] que o README já separou, com a
numeração dele, cada uma com os seus testes. A (1), a (3), a (4) e a (5)
estão **feitas**, no `ee4ea45`, com o [A1-4](#a1-4); e o adversário
delas achou a mesma janela da (3) no `user.run` que um processo pede pela
interface nativa — o processo isolado ou encerrado entre o gate e o
nascimento ganhava um processo livre —, fechada no `6cea470`, com o
nascimento do `fork` refazendo as perguntas do gate dele e as recusas de
quem pede um processo dizendo o processo:

- a (1): o fio `energia` criado no boot, parado, como o do botão;
- a (3): a contenção conferida de novo no nascimento, antes de o filho
  rodar — um `process.isolate` no meio deixa nascer um filho livre;
- a (4): o `process.terminate` de um processo que ainda nasce leva a marca
  ao fio definitivo, sob a mesma trava, e a desconta quando a vaga volta
  por falta de pilha;
- a (5): a recusa da cota num `fork` grava o processo que bifurcou;
- e a mitigação (3) da decisão do A1, que não exclui a alternativa
  adotada, entrou depois, no lote B do #448: o nascimento que não acha
  vaga, havendo morto por recolher, chama o coletor — e, pela mesma razão,
  a recusa da cota com mortos do titular por recolher, na conta do gate e
  na do nascimento —, e quem não nasceu não o espera: ele recolhe na volta
  seguinte, sem esperar o tique, quando ganha a vez (*O chamado do
  coletor*, em [Coordenação](../README.md#coordenação);
  `kernel/src/fios/mod.rs`, `COLETOR_CHAMADO`). O lote B2 acrescentou o
  caso que prova o cutucão no núcleo em que o coletor dorme, e o coletor
  passou a olhar a marca antes de dormir: o chamado que chega durante a
  passada também não espera o tique. O lote B3 pôs a pergunta dentro da
  janela mascarada do sono (`fios::descansar_ate_a_interrupcao_se`): o
  cutucão do chamado que chega entre a pergunta e o sono acorda o sono na
  hora (o item 7 do adversário do lote B2). O lote B4 tirou o `nomem` da
  máscara do ARM: o compilador também não pode tirar a pergunta de dentro
  da janela — o de hoje não a tirava, e a desmontagem do kernel em release,
  antes e depois, é a evidência (o item 3 do adversário do lote B3). A
  pergunta da cota sem efeito,
  `ocupacao_na_cota`, ficou separada da do gate, que chama o coletor. Não
  ajuda com o coletor
  sem a vez, nem com o que esta decisão pergunta: a tabela cheia de vivos
  — de vários titulares, ou da mesma identidade em várias sessões — não
  tem morto por recolher, e o chamado nem acontece.

**As fechadas que ela toca.** A 14.1 (alternativa A, 7/11/2026) e a
alternativa 1 do A1 (8/11/2026): a cota conta os zumbis e os mortos até o
recolhimento. Que só o coletor recolhe é o que está feito, e não uma
decisão fechada: as outras alternativas do A1 ficaram registradas,
"nenhuma descartada" (README.md:5236-5246) — a (4), investigada, não
entrou: traria de volta, pelo `fork`, o defeito do AE-1 —; e a reserva de
vagas aos fios do kernel, uma das três da 14.1 e a (2) do A1, segue aberta
(README.md:8743-8746): recomendá-la, a (c) daqui, não reabre a 14.1. A
autoridade de um processo de agente é da chave (a (b), acima).

### R15-HANDOFF

**O próximo marco da fase 15: o handoff** — as três decisões do marco,
do relatório da continuidade: a **DH-1** (o que é o handoff), a **DH-2**
(quem recebe no destino) e a **DH-3** (para onde continuar). O **DN-4** —
o handoff como o próximo marco — é [B], pela 5.1 e pela 5.2: o roteiro já
o põe primeiro (ver o [DN-4](#dn-4), em As que o coordenador executa).

**O problema.** O roteiro: "O handoff, os recursos remotos, a presença, a
continuidade e os pacotes são os marcos seguintes, e cada um pede uma
decisão própria antes" (README.md:12840-12842). O handoff — passar uma
atividade de um Duke a outro da mesma Pessoa — pede três respostas antes
da primeira linha: o que viaja, e quem solta (DH-1); quem recebe do outro
lado (DH-2); e como a Pessoa diz para onde (DH-3). Hoje, entre dois Dukes
da Pessoa, há a entrega pelo enlace e o fluxo, cada passo pelo gate de
cada lado, e nada que leve uma atividade. As fontes não definem o handoff
além do nome.

**A exposição de hoje.** Nenhuma: não há handoff.

**As evidências.** O [Roteiro](../README.md#roteiro), fase 15; o que fica
de fora na [MALHA](MALHA.md#o-que-fica-de-fora) — "os próximos marcos,
cada um com uma decisão própria antes" —, nos
[FLUXOS](FLUXOS.md#o-que-fica-de-fora) — o handoff e a continuidade; a
retomada, a migração e a recuperação —, no
[ENLACE](ENLACE.md#o-que-fica-de-fora) e no
[PAREAMENTO](PAREAMENTO.md#o-que-fica-de-fora); e o [SDK, O que não
existe](SDK.md#o-que-não-existe). O que existe, e o handoff usaria: o
fluxo entre dois Dukes da Pessoa ([FLUXOS, Entre dois
Dukes](FLUXOS.md#entre-dois-dukes)); a relação que a Pessoa cria no
pareamento, com o nome que ela dá ([PAREAMENTO](PAREAMENTO.md#a-decisão-dn-1-opção-a));
o laço do SDK, que espera a malha, os fluxos e a janela num lugar só; e o
canal de eventos, que já separa a tecla e o ponteiro da máquina (`TECLA`,
`PONTEIRO`) da ação da árvore (`ACAO`, com quem pediu). E as dependências:
a [M-EXEC](#m-exec) (DE-1), o endpoint que muda de programa no `exec` —
fraca —; e a [DT-1](#dt-1), o caminho da Pessoa.

**As alternativas.**

- **DH-1 — o que é o handoff.** (a) Um protocolo de programas sobre a
  malha: o programa da origem manda o estado ao do destino, por um fluxo;
  só o estado viaja — nenhuma sessão, chave, arrendamento ou decisão —; e,
  na dúvida, a origem não solta. (b) **(minha)** Um objeto do kernel que
  leva um endpoint ou uma sessão de um Duke ao outro — esbarra em "nenhuma
  identidade migrada" se levar a sessão. (c) Nada.
- **DH-2 — quem recebe no destino.** (a) O acolhedor da Pessoa: um
  programa dela no destino, que oferece a intenção do handoff; o aceite só
  pela entrada dela; o kernel não lança nada por pedido remoto. (b)
  **(minha)** O kernel do destino lança o programa que a origem pede — um
  pedido remoto que lança código: uma autoridade que a malha não tem. (c)
  **(minha)** O programa que estiver no ar aceita sozinho — o fluxo viraria
  autoridade.
- **DH-3 — para onde continuar.** (a) O nome que a Pessoa deu no
  pareamento — o `dispositivo:<nome>` do espaço dela —; nenhuma lista
  neste marco. (b) **(minha)** Uma lista dos Dukes dela ao alcance — pede
  a presença ([R15-PRESENCA](#r15-presenca)), e esbarra na D7 se descobrir.

**Os riscos.**

- DH-1(a): "na dúvida, a origem não solta" deixa a atividade nos dois
  lados até a confirmação: o protocolo tem de aguentar a duplicata, e o
  destino lê o estado como entrada não confiável — "os bytes são entrada
  não confiável para quem os lê". O que o estado carrega é do programa:
  nada nele é autoridade do Duke, e nenhuma chave do kernel sai.
- DH-2(a): o handoff só termina com a Pessoa diante do destino, e o
  acolhedor tem de estar no ar — lançado por ela. O aceite "só pela entrada
  dela" vale o que vale o caminho da Pessoa: sem a DT-1, outra janela
  imita o pedido de aceite, ou toma o foco dele. Com a recomendação da
  DT-1, o foco não se pede a qualquer hora, e a janela de outro principal
  não o ganha ao abrir — nem o próprio acolhedor, que não toma o foco
  enquanto a Pessoa digita noutra janela (a 2(f)) —; mas o aceite não é
  uma linha de credencial — a 2(b) e a 3(a) não o cobrem —, e uma janela
  que imita o pedido continua possível. Só um aceite pedido no console de
  verdade, depois da sequência da 2(d), não se imita, e ele pede ao kernel
  o que a DH-2(a) não pede: a DH-2 decide se pede o aceite assim, ou se
  fica com a imitação como resíduo escrito.
- DH-3(a): a Pessoa escolhe pelo nome, sem lista; quem tem muitos
  dispositivos lembra os nomes. É o que a D7 permite.

**O impacto.** Os programas: o protocolo, o acolhedor e um exemplo, no
SDK. A política: a intenção do handoff enumerada nos papéis, e o
`fabric.remote` sobre os dispositivos. O kernel: nada de novo nas três (a)
— é o ponto delas. A documentação: um `docs/` do marco, como o FLUXOS e o
SDK. As bancadas de dois Dukes, nas duas arquiteturas e cruzadas.

**A recomendação.** As dadas no relatório da continuidade:

- **DH-1: um protocolo de programas sobre a malha; só o estado viaja; na
  dúvida, a origem não solta**;
- **DH-2: o acolhedor da Pessoa; o aceite só pela entrada dela; o kernel
  não lança nada por pedido remoto**;
- **DH-3: o nome que a Pessoa deu no pareamento; nenhuma lista neste
  marco**.

Depois da DE-1, e da DT-1: o aceite pela entrada da Pessoa pede o caminho
dela — e o que a DT-1 não fecha no aceite, a imitação, a DH-2 decide (ver
os riscos).

**O plano de validação.** Dois Dukes pareados — as bancadas do enlace, do
pareamento e do SDK —, nas duas arquiteturas e nos pares cruzados: a
atividade passa de A a B, a Pessoa aceita em B pelo teclado de B, e A só
solta depois da confirmação. E as recusas: a Pessoa não aceita, e A fica
com a atividade; a ligação cai no meio, e A fica com ela; a relação
esquecida ou revogada no meio; o papel dela sem `fabric.remote`; o
programa de outro titular que tenta receber; o pedido remoto de lançar,
recusado. A auditoria dos dois lados, cada passo pelo gate. As mutações —
a origem que solta antes da confirmação, o aceite por uma `ACAO` da árvore
em vez da entrada da Pessoa, o kernel que lança por pedido remoto —, uma
de cada vez. O adversário: tomar a atividade, aceitar no lugar da Pessoa,
repetir um handoff. A CI completa.

**O que não espera.** Nada de código: o desenho depende das três. A
bancada `cargo xtask sdk` já mede o caminho por onde o estado iria, com os
fluxos entre dois Dukes.

**As fechadas que ela toca.** Nenhuma identidade migrada: a sessão não
viaja, e cada Duke continua ele mesmo (D1, D2). A autoridade remota é a
composição Pessoa ∩ relação ∩ `remoto`, no destino (D4, DF-5). Sem
armazenamento-e-envio (D5): os dois de pé. Sem descoberta (D7): o nome do
pareamento (D8). O fluxo é o transporte, e não autoridade (DF-1 a DF-6); o
aviso só sinaliza (DS-1).

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
- (b), **pela análise deste dossiê, e não das fontes**: fecha o outro
  sistema bootado — a medição dele não é a do Duke —, e não o barramento.
  Com os PCRs certos, quem fala com o TPM depois do boot do Duke ainda
  abre o selo: falta estender um PCR de fecho logo depois de abrir, para
  que nada mais o abra até o boot seguinte. E, num TPM discreto, quem está
  no barramento forja as extensões. Com o PTT — o TPM do firmware da
  Intel, uma das duas peças da máquina de referência (OPERACAO.md:68) —
  não há barramento de fora, e fecha.
- (b2) concentra numa chave o que hoje pede o quórum.
- (c) a lista de fabricantes muda, e o `swtpm` da bancada não tem cadeia
  de fabricante.
- Só a (b) muda a política dos selos que o B2 e o ICP-5 fecharam sem
  medição: o da identidade não tem política, só a senha vazia e o
  primário deste TPM (`ancora/src/cofre.rs:54-64`); o das chaves, o
  `TPM2_PolicyNV` da geração (PERSISTENCIA.md:1384-1387). O B2 deixou a
  medição de fora de propósito — "prendê-lo à medição do boot é o boot
  seguro, que fica fora daqui" —, e o ICP.md chama o boot medido de
  decisão nova. Não é reabrir a escolha do B2 — a chave nasce no primeiro
  boot e fica no TPM —, mas é mudar o que abre o selo: por isso a (b) é
  [C]. A (a) e a (c) são [C] por outra razão, sem tocar nos selos: uma
  raiz de confiança nova — a chave do projeto no firmware, ou os
  fabricantes.

**O impacto.** O iniciador (medir; na (a), conferir a assinatura); o kernel
— `tpm.rs`, `identidade.rs`, a persistência e o cofre: as políticas dos
selos e a reconciliação do boot —; a atualização (selar de novo ao armar,
na (b1)); o `xtask` — as bancadas com o `swtpm` medindo, a imagem de
produção —; as máquinas de referência; a documentação de OPERACAO,
ATUALIZACAO e PERSISTENCIA.

**A recomendação.** (b) com (b1): é o que fecha a exposição do outro
sistema bootado — os segredos presos ao código conferido — sem mudar quem
confia em quê na atualização; e, **(minha)**, o PCR de fecho depois de
abrir. O barramento de um TPM discreto continua de fora; a máquina de
referência com o PTT o fecha. A (a) depois, como opção do operador, nas
máquinas cujo firmware a aceite; a (c) depois das duas; a (b2) não, sem
uma decisão à parte.

**O plano de validação.** A bancada com o `swtpm` medindo, nas duas
arquiteturas: um kernel mudado no slot não abre a identidade nem as
chaves; depois do PCR de fecho, um pedido ao TPM no mesmo boot também não;
a atualização A/B arma, sela de novo e boota a versão nova com os
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

## As outras

Na ordem recomendada. Cada uma: o problema, as alternativas, a
recomendação provisória e o que destrava; as do lote rápido — a AUD-ANEL,
a P-HISTORIA, a AUD-JUNTO e a AUD-FALHA — também os riscos, o impacto e o
plano de validação, para se decidirem sem outra rodada.

### AUD-ANEL

**Os registros do boot que saem do anel antes do journal** — o achado 4
do adversário do B4 da auditoria.

- **O problema.** A continuação leva só o anel da cadeia do boot: mais de
  1024 decisões antes de o journal ser lido perderiam as primeiras, sem
  lacuna. Hoje o boot faz uns poucos registros antes
  ([PERSISTENCIA](PERSISTENCIA.md#a-reconstrução-da-auditoria-no-boot-b4),
  "O que o adversário achou").
- **A área de 5.3.** A semântica da auditoria: uma lacuna nova na cadeia.
- **As alternativas.** (a) Marcar a perda — "uma lacuna com o elo de
  outra numeração — semântica nova, uma decisão [C]". (b) Aceitar, como
  limitação escrita: o de hoje.
- **Os riscos.** (a) muda a cadeia: um registro de lacuna, com o elo de
  outra numeração, que o `audit.verify`, a reconstrução do boot, o NSF —
  que já lê a lacuna do anel como degradação — e a bancada de persistência
  precisam reconhecer; uma lacuna marcada errado esconde uma perda de
  verdade. (b): a perda continua possível, e calada, se um incremento
  puser mais de 1024 decisões no boot antes de o journal ser lido.
- **O impacto.** (a): `politica::auditoria` — a cadeia e o registro de
  lacuna —; a reconstrução da auditoria no boot, na persistência — a
  continuação e a adoção do B4, numa tomada só, que o `cargo xtask
  invariantes` confere —; o `audit.verify`; o NSF; o PERSISTENCIA. (b):
  nada.
- **O plano de validação.** (a): um caso que põe mais de 1024 decisões
  antes de o journal ser lido — por um gancho da suíte — e confere a lacuna
  marcada, a cadeia que se verifica de ponta a ponta e o NSF que a vê; a
  bancada de persistência com o corte de energia no meio da reconstrução;
  a mutação, a perda sem a marca; as duas arquiteturas. (b): **(minha)** um
  caso que conta as decisões do boot antes do journal e reprova perto do
  anel — o aviso, [B], de que a (a) ficou necessária.
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
- **Os riscos.** (a): a base resumida não pode perder uma lápide (R1) nem
  deixar a âncora ver um estado anterior (R6); as decisões que levaram a
  um estado, e não o fixaram por último, saem da base; e uma base no
  formato de hoje precisa migrar. (b): uma máquina com muitas operações
  para — fechada, mas parada —, e a saída é reinstalar, que perde tudo.
- **O impacto.** (a): o formato da base do journal de estado — uma versão
  nova —, a compactação, a reposição no boot e a migração, na persistência
  e no `diario`; o PERSISTENCIA. (b): nada — a medida é [B] e não espera.
- **O plano de validação.** (a): a bancada de persistência com uma
  história longa sintética — dezenas de milhares de operações —,
  compactada e resumida, e o boot que repõe o mesmo estado; as lápides
  inteiras; o corte de energia em cada fronteira da compactação; a
  migração de uma base no formato de antes; as mutações — a lápide que sai
  do resumo, a credencial que volta a um estado anterior —; as duas
  arquiteturas. (b): a medida de quanto a base cresce por operação, na
  bancada.
- **As fechadas.** A R1 e a R6, e a 1.7 — a auditoria e a proveniência
  existentes: a (a) tira da base as decisões que não fixaram o estado
  final.
- **A recomendação provisória.** (b), medindo quanto a base cresce por
  operação, para saber quando a (a) vira necessária.
- **Destrava.** A vida longa de uma máquina.

### AUD-JUNTO

**A decisão de uma mudança no mesmo registro do journal que ela, ou
antes** — o que a CI 509 mostrou, no pareamento.

- **O problema.** A documentação promete que a decisão que autorizou uma
  mudança de autoridade vai no mesmo registro do journal que a mudança —
  "a mudança e a decisão entram juntas, ou nenhuma entra" —, e nunca num
  anterior ([PERSISTENCIA](PERSISTENCIA.md#a-auditoria-no-journal), "A
  decisão vai no registro da operação"; o README, "A auditoria também"; e
  a documentação do módulo, de `gravar_sozinho` e de `concluir`, em
  `kernel/src/persistencia.rs`). O código garante menos onde a decisão é
  registrada antes de a ordem das gravações ser tomada. O gate registra a
  decisão antes de o handler tomar a ordem, e nessa janela o coletor — que
  grava a auditoria pendente a cada dois segundos, ou na hora, com meio
  anel esperando ou com um pedido de dados esperando lugar no caminho da
  auditoria — ou a gravação de outro fio pode levá-la num registro
  anterior: um só de auditoria, ou o da operação do outro fio. Depois,
  `gravar_sozinho` acha a decisão já gravada e grava a mudança sem ela,
  sem erro. A documentação de `gravar_com_a_decisao` chega perto — "junto
  — ou antes, num registro só de auditoria" —, sem o registro da operação
  de outro fio. Só o
  [ARMAZENAMENTO](ARMAZENAMENTO.md#a-ordem-de-uma-mutação) diz o que o
  código faz — a decisão pode ir antes, levada pelo coletor —, e o armazém
  o contorna: o registro da execução, que cita a decisão, é feito com a
  ordem na mão e vai no registro do commit (`kernel/src/armazem.rs`,
  `mudar_em_ordem`). As operações administrativas, a troca da própria
  senha e a gravação do pareamento registram a decisão com a ordem na mão,
  e o que se diz delas vale.
- **A evidência.** A CI 509: "pareamento: esquecer e parear de novo"
  reprovou no boot pela UEFI do ARM, na parte 2 de 2, porque um caso
  anterior deixou o coletor solto, e ele levou a decisão de um
  `device.forget` num registro só de auditoria, antes do da desfeita
  (`kernel/src/pareamento.rs`, `esquecer_pelo_comando`: a decisão é do
  gate, e a ordem é tomada depois). Com uma espera de 2,5 segundos posta
  antes da tomada da ordem, só numa rodada de experimento, e o coletor
  solto, o caso reprova sempre; com o coletor pausado, passa. A suíte
  pausa o coletor, e agora o confere depois de cada caso; fora dela, a
  janela é a de todo dia.
- **O que vale e o que não vale.** Vale: a decisão nunca vai depois da
  mudança; uma mudança no disco tem antes dela, na cadeia, a decisão — ou,
  se a decisão saiu do anel na janela, com mais de 1024 registros entre
  ela e a gravação, e outro escritor gravou primeiro a lacuna que a cobre,
  essa lacuna: a recusa de `gravar_sozinho` à decisão perdida só vê a
  lacuna que a própria gravação leva —; e a reposição refaz a cadeia de
  qualquer registro. Não vale a atomicidade: depois de uma queda entre os
  dois registros, o disco tem a decisão sem a mudança — como uma decisão
  cuja execução falhou, mas sem o registro da falha.
- **A área de 5.3.** A semântica da persistência e da auditoria: a
  garantia escrita do que o journal guarda junto.
- **As alternativas.**
  - (a) Escrever a garantia real — a decisão junto ou antes, nunca depois;
    perdida na janela, a lacuna antes —, e o que uma decisão sem a mudança
    quer dizer depois de uma queda, em todo lugar que promete o mesmo
    registro (ver o impacto). Só documentação.
  - (b1) O kernel cumprir o escrito: o gate registra a decisão de uma
    mudança com a ordem das gravações na mão — espera o journal em toda
    decisão de mudança —, como já fazem as operações administrativas, a
    troca da própria senha e a gravação do pareamento.
  - (b2) O coletor e as gravações de outros fios não levam a decisão de um
    comando ainda em execução.
  - (b3) O padrão do armazém: cada mudança decidida pelo gate grava, com a
    ordem na mão, a execução que cita a decisão, no mesmo registro da
    mudança — a decisão pode ir antes; a execução, nunca. A gravação exige
    a execução, e não a decisão, neste registro, e a documentação diz isso
    no lugar da promessa de hoje.
  - (c) Deixar como está.
- **Os riscos.** (a): nenhum no código; a garantia escrita fica mais
  fraca, e quem lê a auditoria depois de uma queda tem de saber que uma
  decisão sem a mudança pode ser a de uma mudança que não chegou ao disco,
  e que uma mudança com a lacuna antes pode ter perdido a decisão. (b1):
  latência e contenção no gate, serializado com o disco, em toda decisão
  de mudança. (b2): um comando longo ou suspenso segura a drenagem, e o
  anel pode perder registros; mais estado no caminho da auditoria. (b3):
  um registro de auditoria a mais por mudança de autoridade, que é rara; e
  cada caminho de mudança precisa gravar a execução dentro da ordem — um
  que esqueça volta ao de hoje, e o `xtask` pode conferir quem conclui sem
  ela. (c): a documentação continua prometendo o que o código não faz.
- **O impacto.** (a): a documentação dos caminhos em que a decisão é
  registrada antes de a ordem ser tomada — o PERSISTENCIA ("A decisão vai
  no registro da operação" e o `key.create`), o PAREAMENTO (o
  `device.forget`), o README ("A auditoria também", o `key.create` na
  tabela de comandos, a tabela e o roteiro do armazém), a documentação de
  `kernel/src/persistencia.rs` (o módulo, `gravar_sozinho`, `concluir`,
  `gravar_operacao` e `gravar_atualizacao`), de `kernel/src/slots.rs`, de
  `kernel/src/armazem.rs` e de `kernel/src/agent/commands.rs` — e o resumo
  do `key.create`, que o `agent.describe` mostra. (b1): o gate e a ordem
  das gravações, em `kernel/src/autorizacao.rs` e
  `kernel/src/persistencia.rs`, para toda decisão de mudança. (b2): o
  coletor, a drenagem e o anel da auditoria. (b3): os caminhos de mudança
  que concluem fora do padrão do armazém — o `device.forget`, o
  `key.create`, a atualização (`slots.rs`) e os que usam `concluir`,
  `gravar_operacao` e `gravar_atualizacao` —; `gravar_sozinho`, cuja
  exigência passa à execução; e a mesma documentação da (a), com a
  garantia nova.
- **O plano de validação.** (a): o revisor confere os textos contra o
  código; um caso da suíte solta o coletor na janela — por um gancho
  antes da tomada da ordem num handler — e confere que a decisão foi num
  registro anterior e que a mudança está no disco com a decisão antes
  dela; outro faz a decisão sair do anel na janela e confere a mudança com
  a lacuna antes. (b1), (b2) e (b3): os mesmos casos, conferindo o mesmo
  registro — a decisão na (b1) e na (b2), a execução que a cita na (b3)
  —; a bancada de persistência com os cortes de energia; a medida da
  latência do gate (b1) e da perda do anel sob carga (b2); e, na (b3), a
  mutação de um caminho sem a execução, que o caso e o `xtask` acusam.
- **As fechadas.** A 1.7 — a auditoria e a proveniência existentes: a (a)
  não muda nenhuma das duas; a (b1) e a (b2) mudam o caminho da
  auditoria, não o que ela registra; a (b3) acrescenta, por mudança, o
  registro de execução que o armazém já grava.
- **A recomendação provisória.** (b3). Ela usa o mecanismo que o armazém
  já usa e documenta, sem latência nova no gate nem estado novo no
  coletor, e dá uma garantia que o código cumpre e confere: a mudança e a
  execução que cita a decisão entram juntas, ou nenhuma; a decisão, junto
  ou antes. A (a) é a alternativa mínima — nada de segurança muda, porque
  a decisão nunca vai depois da mudança, e a que se perde fica marcada
  antes dela, como lacuna —, mas deixa implícita a ligação entre a mudança
  e a decisão, e a perde junto com a decisão que sai do anel.
- **Destrava.** Nada do roteiro; a documentação passa a dizer o que o
  código faz.

### AUD-FALHA

**A morte de um processo por uma falha, na auditoria** — do #451, no lote
B do #448.

- **O problema.** Um processo que lê o contador de ciclos — desde o #451,
  fora do anel 3 e do EL0 —, que executa uma instrução privilegiada ou
  que lê a memória do kernel morre pela falha — a de proteção, ou a de
  página, na leitura da memória do kernel. Desde o lote B2, toda exceção
  que o processo provoca no anel 3 e no EL0 o mata do mesmo jeito — a
  divisão por zero, o `ud2`, o passo do `TF`, o `brk` do ARM —, menos a
  verificação da máquina (`#MC`) e o SError do ARM, que são do hardware e
  continuam parando a máquina. O lote B3 acrescentou as mortes do que ele
  prende: o ponto flutuante e o SIMD (o `#NM` no x86, a classe 0x07 no
  ARM), o seletor do LDT (`#GP`), o `wfi` e o `wfe` do EL0 que iriam
  dormir (a classe 0x01), o `msr daif` do EL0 (a classe 0x18) e o
  `sysenter` (`#UD`; `#GP(0)` num Intel). E fechou os dois caminhos até a
  máquina parada que o adversário do lote B2 achou: o passo adiado por um
  `mov ss`, num processador — o `#DB` do anel 0 com o `BS` como única
  causa volta sem o `TF`, e o processo morre do passo na volta da
  chamada —, e o LDT do reset — o LDT nulo em todo núcleo faz do seletor
  do LDT um `#GP` que mata o processo, e a falha de página também culpa o
  processo pelo `CS` do quadro. O lote B4 acrescentou as mortes do que ele
  prende: o `str`, o `sldt`, o `smsw`, o `sgdt` e o `sidt` do anel 3 (o
  `#GP(0)` do UMIP, num processador que o tem), o `fwait` (o `#NM`, pelo
  `CR0.MP`) e o canal do depurador do EL0 (a classe 0x18, pelo
  `MDSCR_EL1.TDCC`).
  O log diz qual e onde (`processo morto por ... em pc=...`), e a
  contabilidade das falhas a conta (`traps`), mas a auditoria não diz
  nada: a morte por uma falha não é uma decisão, e nunca teve registro —
  nem a saída normal de um processo tem (`kernel/src/usuario/mod.rs`, só o
  log). O NSF, que lê a auditoria, não vê um processo que sonda o kernel
  por falhas.
- **A área de 5.3.** A semântica da auditoria: um registro novo, que não é
  uma decisão.
- **As alternativas.**
  - (a) Deixar como está: o log e a contabilidade das falhas, sem
    registro.
  - (b) Um registro do kernel para toda morte por falha — um método novo,
    com o processo, a falha e o pc. O registro não pode ser gravado no
    tratador da exceção, e vai adiado, pelo coletor.
  - (c) **(do especialista do lote)** Só as falhas de instrução
    privilegiada e de contador, adiadas e com teto: menos volume, e uma
    regra de seleção nova.
- **Os riscos.** (a): o NSF segue cego às sondagens por falha. (b) e (c):
  um método novo na auditoria, que o NSF, o `audit.verify` e a
  reconstrução do boot precisam reconhecer; o volume — um processo que
  lança filhos que falham em série enche o anel, limitado pela cota de
  processos do titular —; e o registro adiado, que uma queda entre a morte
  e a gravação perde.
- **O impacto.** (b) e (c): `politica::auditoria` (o método), os
  tratadores das exceções nas duas arquiteturas e a fila até o coletor
  (`traps`, `fios`), o NSF (`seguranca`, o sinal), os casos `contador:` e
  os das exceções do usuário (`excecoes:`), que os lotes B2 e B3
  acrescentaram.
  (a): nada.
- **As fechadas.** A 1.7 — a auditoria e a proveniência existentes: a (a)
  não muda nada; a (b) e a (c) acrescentam um registro, sem mudar os de
  antes, e o `audit.verify` e a adoção no boot têm de reconhecê-lo.
- **O plano de validação.** (b) e (c): os casos `contador:` e os das
  exceções do usuário conferem o registro, com o processo e a falha; as
  mutações — o registro ausente, e o registro sem o processo —; a cadeia,
  a adoção no boot e o volume sob uma rajada de mortes; as duas
  arquiteturas.
- **A recomendação provisória.** (a) agora; (c) se o NSF precisar do
  sinal. Antes do lote B2, no x86, uma exceção do anel 3 que não fosse #GP
  nem #PF — o `int3` já era um #GP — parava a máquina, e no ARM o `brk` do
  EL0 com os imediatos do estouro de propósito também — e com ela o fim da
  auditoria que ainda não tinha ido ao journal —; o lote B2 as faz matar o
  processo, como as outras — e o lote B3, que prende o ponto flutuante e
  o SIMD, faz morrer também o programa de fora que os use —, e é por eles
  que a morte por falha fica um evento comum, que esta decisão pergunta se
  a auditoria grava.
- **Destrava.** Nada do roteiro; um sinal novo para o NSF.

### R13-CONSENT

**O consentimento — a Pessoa perguntada, e o registro que ela lê.**
Decidido com a [ALC-TEMP](#alc-temp) (DX-1).

- **O problema.** A fase 13 promete quem pediu, o que foi feito, e "um
  registro que a pessoa possa ler depois e desfazer". As duas primeiras
  existem: a auditoria grava o titular, a sessão, o processo e o programa
  de cada decisão, e o console diz `executado: … (agente N)` ou
  `(pessoa)`. Falta perguntar: "um `set_value` do agente troca o que a
  pessoa estava digitando, e nada pergunta a ela antes" ([Operar por uma
  pessoa](../README.md#operar-por-uma-pessoa), "O que ainda não há") —
  hoje, o que separa os dois é o arrendamento, e "pessoa e agente estão no
  mesmo nível" ([Coordenação](../README.md#coordenação)). E falta o
  registro que a Pessoa lê: o `audit.tail` exige `audit.read`, que o
  `observador` e o `operador` não têm ([OPERACAO, Os comandos de todo
  dia](OPERACAO.md#os-comandos-de-todo-dia)).
- **A exposição de hoje.** Baixa: um agente com `ui.act` edita o campo que
  a Pessoa largou — passado o arrendamento dela — sem perguntar, e a
  edição fica gravada; a Pessoa não lê o que fizeram em nome dela.
- **As alternativas.** (a) **(minha, pelo precedente do quórum)** A
  política marca as permissões que, pedidas por um agente sobre o que é da
  Pessoa, pedem a confirmação dela, no caminho dela (DT-1); o gate decide
  de novo com a confirmação — uma decisão que espera alguém, um desfecho
  novo no gate. (b) A expansão temporária — a [ALC-TEMP](#alc-temp) (DX-1),
  na forma que o relatório da continuidade recomendou, o papel com prazo
  —: consentir é dar o papel, e o gate decide como sempre. Quem o dá — só
  o administrador, com prova, ou também a Pessoa, contido no papel dela
  (**(minha)**, pelo precedente do [D8](PAREAMENTO.md#a-decisão-dn-1-opção-a),
  em que ela cria sem o administrador uma relação cujo papel cabe no dela)
  — é a pergunta que o consentimento traz à DX-1. (c) **(minha)** Só o
  registro: a Pessoa lê a auditoria do que foi feito em nome dela, ou no
  que é dela — um alcance novo de leitura —, e nada se pergunta antes. (d)
  Nada.
- **Os riscos.** (a) para a automação de um agente no humano; e a
  confirmação não é uma linha de credencial: sem a DT-1, ela se imita, e
  com a DT-1 recomendada também, a menos que seja pedida no console de
  verdade, depois da sequência da 2(d) — uma pergunta nova no kernel. (b)
  é autoridade dada por um tempo: o teto, a enumeração e o fim — o prazo
  pelo tempo lógico, que pode parar depois de um salto do civil para trás;
  a revogação de quem deu e de quem recebeu — têm de ser da própria
  política, e não de uma tabela ao lado, senão é uma segunda autorização.
  (c) não pode mostrar à Pessoa o que é de outros, nem o que uma resposta
  cala — o mesmo `DENY_RESOURCE` para o que não existe e o que é de outro.
- **A recomendação provisória.** (b) + (c), depois da DT-1; a (a) não, por
  ora: uma decisão que espera é um mecanismo novo no gate, e a (b) dá o
  mesmo controle sem ele. Não se delega identidade: o agente continua ele
  mesmo, com mais alcance por um tempo.
- **As fechadas.** Nenhum `ALLOW(*)`: o papel é enumerado. A Policy como
  fonte da decisão. Nenhuma autorização paralela. [O teto não é
  posse](../README.md#o-teto-não-é-posse). E a R1: a revogação não tem
  volta.
- **Destrava.** O título da fase 13; o [R13-DESFAZER](#r13-desfazer).

### ALC-TEMP

**A expansão temporária de alcance, por titular** — a **DX-1** do
relatório da continuidade. Decidida com o [R13-CONSENT](#r13-consent),
alternativa (b).

- **O problema.** Hoje o alcance é do papel, e o que muda o papel é
  `policy.write` e `policy.assign`, com prova, até a próxima mudança. Uma
  expansão temporária, por titular — "esta pessoa, este recurso, por uma
  hora" — é um conceito que a política não tem: uma entrada com prazo, de
  uma identidade e não de um papel, que vence pelo tempo lógico e
  sobrevive a um boot. "Isso não se infere das invariantes" ([README,
  Decisões pendentes](../README.md#decisões-pendentes);
  [USABILIDADE](USABILIDADE.md#decisões-novas--para-quem-decide)).
- **As alternativas.** (a) A entrada com prazo, por identidade e por
  recurso, na política — a forma da USABILIDADE. (b) O papel com prazo — a
  atribuição que vence, o `policy.assign` com fim —, sem entrada por
  recurso: o alcance continua do papel. (c) Nada: o administrador muda o
  papel e o desfaz à mão.
- **A recomendação.** A dada no relatório: **esperar um consumidor;
  depois, o papel com prazo** — a (b). O consumidor à vista é o
  consentimento.
- **Destrava.** O consentimento da fase 13.

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
  salva os registradores de SIMD de um processo quando troca de processo.
  Até o lote B3 do #448, dois programas que os usassem passavam o estado
  de um ao outro, sem erro — um canal entre titulares, por fora do gate,
  que o adversário do lote B2 mostrou. Desde o lote B3, o kernel prende o
  ponto flutuante e o SIMD no anel 3 e no EL0 — o `CR0.TS` no x86, o
  `CPACR_EL1` em zero no ARM —, e o programa que os usa morre na primeira
  instrução, com a falha contada. Os alvos (`x86_64-unknown-none`,
  `aarch64-unknown-none-softfloat`) e as opções dos pacotes de cifra
  (`programas/.cargo/config.toml`) o garantem para os programas do
  repositório, e o `xtask` confere o kernel e os programas do x86 da
  imagem (`conferir_sem_simd`: o SIMD, o x87, o MMX e, desde o lote B4,
  as máscaras do AVX-512, o AMX, o Key Locker e o que o `llvm-objdump` não
  sabe ler). Desde o lote B4, o `XCR0` também é o
  do kernel em todo núcleo — o x87, o SSE e o AVX que o processador
  declara, e nada mais (`xcr0_do_kernel`) —: o AVX-512 e o AMX ficam
  desligados, e o AMX, que não confere o `CR0.TS`, é `#UD`. O `TPIDR_EL0`
  do ARM e os seletores de dados do x86, que o lote B4 passou a guardar
  por fio, não são estado de SIMD e não mudam o que esta decisão decide.
  O custo: o ChaCha20-Poly1305 em software, 317
  MiB/s no hospedeiro, contra 104 do AES-128-GCM — por isso ele vai
  primeiro ([O TLS de um programa](../README.md#o-tls-de-um-programa)) —, e
  o SHA-256 do BLS do IC, em software ([ICP](ICP.md#as-bibliotecas)).
- **O que a decisão fixa.** Se o kernel salva o estado de SIMD de cada
  processo, e quando; quais componentes do `XCR0` o kernel liga — hoje o
  x87, o SSE e o AVX —; quanto isso custa em memória por fio e em tempo de
  troca; e a forma binária dos programas — os alvos e as opções —, que o
  contrato v2 inclui.
- **As alternativas.** O roteiro só nomeia a decisão; as duas primeiras
  são **(minhas)**. (a) Salvar sempre, em toda troca de processo — o
  estado de um processo nunca fica no registrador enquanto outro roda: a
  troca preguiçosa é a do vazamento de estado de ponto flutuante entre
  processos conhecido desde 2018 (o LazyFP). (b) Salvar só para os
  programas que o declaram no manifesto. (c) Como hoje, desde o lote B3:
  o ponto flutuante e o SIMD presos, e o programa que os usa morre.
- **A recomendação provisória.** (a), medida — a memória por fio e o tempo
  da troca —, e só depois a mudança dos alvos dos programas, numa versão
  da interface nativa: num kernel que não o salva, um programa compilado
  com SIMD morre na primeira instrução.
- **As fechadas.** O DS-2: a forma binária do programa — o ELF dos dois
  alvos — é contrato (SDK.md:69-72), e o que não é crescer é só numa
  versão maior, por decisão própria (SDK.md:84-86): mudar os alvos é uma
  versão nova da interface nativa.
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
  o roteiro põe antes do mTLS (README.md:12706-12707), não está nem entre
  os feitos nem entre os que pedem decisão (README.md:12732-12734):
  conferir o estado dela.

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

- **A avaliação**, [B], está feita: o [QUIC](QUIC.md). Ela responde às
  três perguntas desta entrada. A associação UDP de hoje filtra o par como
  a RFC 9000 §9 pede do cliente, e a conexão — só o cliente, um caminho,
  sem migração, sem endereço preferido, sem 0-RTT — cabe no gate de hoje,
  numa associação `udp:` decidida pelo destino. Seguir uma mudança de
  caminho pelo próprio programa, por um `net.connect` novo, é [B]. O que o
  caminho pede além disso: o relógio ([C]); o buffer da associação, o lote
  de datagramas por decisão e o modo QUIC do `rustls` sem `std` ([B]).
- **O problema.** Nenhum consumidor do Duke ganha com o HTTP/3: o IC está
  fora pelo grupo C, o HTTP/2 já multiplexa, e o que o HTTP/3 traz — a
  perda sem segurar as outras correntes, uma volta a menos — não aparece
  numa bancada sem perda e com a volta abaixo de um milissegundo. O custo,
  de três a cinco incrementos do tamanho do HTTP/2 **(minha)**, é certo.
- **As decisões do caminho**, no formato curto, no
  [QUIC](QUIC.md#as-decisões-c):
  - **R12-QUIC-RELOGIO** — o relógio do programa no ritmo dos pacotes. A
    única no caminho. Recomendação provisória: nenhuma enquanto o HTTP/3
    estiver adiado; com a necessidade, o instante no resultado do
    `net.recv` e do `net.send` da associação.
  - **R12-QUIC-0RTT** — os dados antecipados e a retomada. Recomendação:
    não.
  - **R12-QUIC-CAMINHO** — a mudança de caminho seguida pelo kernel.
    Recomendação: nunca.
- **A recomendação provisória.** Adiar o HTTP/3 e o QUIC até haver um
  consumidor; esta entrada fica no índice como o lembrete da R12-QUIC-RELOGIO,
  que se decide só quando ele vier.
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

### R15-REMOTOS

**Os recursos remotos.** Como os outros marcos da fase 15, "cada um pede
uma decisão própria antes" ([Roteiro](../README.md#roteiro), fase 15); as
fontes não os definem além do nome, e o sentido abaixo é o comum.

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
  [PAREAMENTO](PAREAMENTO.md#o-que-fica-de-fora)). E a D3: o enlace tem
  "um conjunto fechado de mensagens" (ENLACE.md:35-38) — a (a) o cresce.
- **As alternativas.** (a) **(minha)** A presença só entre os já
  relacionados, pelo endereço da relação — uma mensagem a mais no conjunto
  fechado do enlace. (b) A descoberta local — esbarra na D7, e não se
  propõe aqui. (c) Nada.
- **A recomendação provisória.** (a). O handoff não espera por ela: a
  DH-3 escolhe pelo nome do pareamento, sem lista.

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
- **A recomendação provisória.** (a), depois do
  [handoff](#r15-handoff): o roteiro o põe antes — o [DN-4](#dn-4) —,
  porque ele bloqueia a continuidade.

### R15-PACOTES

**Os pacotes.**

- **O problema.** "Não há gerenciador de pacotes, repositório,
  dependências entre programas nem atualização de programas: o programa é
  um arquivo selado" ([SDK, O que não existe](SDK.md#o-que-não-existe)).
- **As limitações de hoje.** O selo de código da fase 13 não tem
  revogação de um selo nem de uma versão, nem cadeia de editores; a
  confiança é do papel no editor ([O código de fora da
  imagem](../README.md#o-código-de-fora-da-imagem)).
- **As fechadas.** O DS-2: o contrato v2.
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

## As que o coordenador executa

Estas o coordenador classificou como [B] pela 5.3 — a classificação é dele
([5.8](../CLAUDE.md#58-a-responsabilidade-do-coordenador)) —, e elas não
esperam a palavra do dono: não são decisões dele, e não entram no índice
nem na ordem. Ficam aqui porque o dono viu algumas no relatório da
continuidade ou na pendência #298, e porque as decisões abertas as citam.
A alternativa de uma delas que tocaria uma área de 5.3 — a (c) da I7, a
(c) da R12-IC-NOS — não se propõe: se um dia se propuser, entra no índice
como [C].

| Id | O que se faz | O estado |
|---|---|---|
| [A1-4](#a1-4) | a recusa da cota diz quantos dos contados são mortos que esperam o coletor | feito, no `ee4ea45` |
| [F4](#f4) | o `exec` decide de novo no ponto sem volta | feito, no `869dc08`, e o resto que o adversário do lote achou, no `97ea728`; o que o adversário da integração achou, no lote A3 do #448; o desfecho da imagem que não se carrega e o das recusas sobre quem pede, e o erro do `exec` da imagem que não se confere, no lote A4; o que o adversário do lote A4 achou, no lote A5; o que o adversário e o revisor do lote A5 acharam, no lote A6; o que o adversário e o revisor do lote A6 acharam, no lote A7; e o que o adversário do lote A7 achou, com o fecho das guardas de texto por inventário, no lote A8; e o que o adversário e o revisor do lote A8 acharam — as fontes que o inventário não fechava —, no lote A9; e o que o adversário e o revisor do lote A9 acharam — a guarda de fora do cargo, que confiava no `cargo` que resolvia —, no lote A10 |
| [I7](#i7) | o comando que existe, num console sem ninguém, gravado sem o resumo dos parâmetros | feito, no lote B do #448; a troca da própria senha com algo na linha, no lote B2 |
| [A9-RESUMO](#a9-resumo) | o resumo de 16 dígitos na descrição de um programa | feito, no lote B do #448; o que o adversário do lote achou — o número da regra do firewall que se perde no corte, e o par misturado de duas descrições inteiras — no lote B2 |
| [DN-4](#dn-4) | o handoff como o próximo marco da fase 15 | decidido pelo roteiro |
| [SDK-CANAL](#sdk-canal) (DC-1′) | o canal sem nome | documentado, até um consumidor pedir |
| [R12-IC-NOS](#r12-ic-nos) | os nós da rede principal achados pela árvore de estado, e escritos na política pelo administrador | no roteiro da fase 12, quando houver um consumidor |

### A1-4

**O que a recusa da cota mostra** — o achado A1-4 do adversário da
alternativa 1.

- **O problema.** A recusa — "cota de processos do papel: N de M" — conta
  os mortos que esperam o coletor, e o `process.list` não os mostra: quem
  a ouve vê menos processos do titular na lista ([README, Decisões
  pendentes](../README.md#decisões-pendentes)).
- **O que se faz.** A recusa diz quantos dos contados são mortos que
  esperam o coletor. Muda o texto do detalhe da auditoria, que não é
  contrato (SDK.md:88-93), como a correção (5) da
  [COTA-SOMA](#cota-soma); o `process.list` fica como está.
- **O estado.** Feito, no `ee4ea45`: `cota de processos do papel: N de M,
  K mortos por recolher` (ou `1 morto por recolher`), da mesma conta, na
  mesma seção crítica que recusou.

### F4

**O ponto sem volta do `exec`** — o F4 do adversário do AE-1, na
pendência #298.

- **O problema.** O `executar` decide `process.run` sobre o caminho —
  gravado com o método `process.exec`, em nome do processo
  (`kernel/src/usuario/mod.rs:1397-1401`; README.md:6874-6876) — antes de
  ler o arquivo; depois lê e confere o código — o selo, pela confiança de
  agora —, prepara a imagem e troca no ponto sem volta com o ALLOW de
  antes, sem decidir de novo. Uma revogação, uma política nova ou uma
  contenção que chegue durante a leitura — a troca para o `livro` levou de
  370 a 970 ms na suíte ([FLUXOS, Os estados](FLUXOS.md#os-estados)) — não
  para a troca. Depois dela, cada pedido da imagem nova passa pelo gate
  com a política de então.
- **O que se faz.** Decidir de novo no ponto sem volta, pelo padrão do
  `reconfirmar` — a mesma conta do gate, com o registro, a política e a
  contenção de agora (`kernel/src/autorizacao.rs:2098-2118`) —, como a
  correção (3) da [COTA-SOMA](#cota-soma) confere de novo a contenção no
  nascimento. **[B] pela 5.3 — o coordenador executa; fazê-lo sem trazer
  de volta o defeito do AE-1 é escolha de implementação.** O defeito é a
  espera da ordem das gravações dentro da chamada de sistema. A ponta de
  um fluxo já troca com a ordem na mão; para as outras, decidir de novo
  sem ela estreita a janela à troca e não a fecha — a revogação se ordena
  pela ordem das gravações.
- **O estado.** Feito, no `869dc08`, com o resto das últimas palavras do
  gate:
  - o `executar` decide de novo imediatamente antes de `trocar_a_imagem`,
    com a mesma conta do gate (`conta_da_chamada`), sobre a mesma
    permissão e o mesmo caminho. A ponta de fluxo decide de novo dentro
    da tomada sem esperar da troca, com a ordem na mão; quem não é ponta,
    sem a ordem e sem esperá-la, e a janela fica estreitada à troca, como
    acima. Recusada, a preparada sai, a execução da decisão vai à
    auditoria com o código e o motivo, e o processo ouve `NEGADO`;
  - o `reconfirmar` pergunta também se quem pede acabou ou tem o fim
    pedido, e refaz a confiança no editor; as perguntas sobre quem pede um
    processo recusam o programa que não se sabe, em vez de supor, e
    perguntam pelas revogações que um journal recusado perdeu;
  - a recusa do `user.run` no passo do gate responde o código e o motivo
    de verdade;
  - 13 casos (`kernel/src/testes/nascimento.rs` e
    `kernel/src/testes/fluxo/troca.rs`, cada um da troca com a ponta de
    fluxo e sem) e 12 mutações, todas reprovadas.

  O adversário do lote achou um resto, médio: a decisão de novo pergunta
  pela confiança no editor do programa de quem chama — a imagem antiga —,
  e não pelo da imagem nova, conferido antes da preparação; o nascimento
  do `user.run`, o mesmo. E, baixos, o `exec` de quem tem o fim pedido sem
  o isolamento, o detalhe "processo isolado" de quem está só encerrado, e
  o `explain` errado das recusas da cota. Foram a correção seguinte, [B],
  no `97ea728` (o lote A2 do #448): as mesmas perguntas, onde a janela
  acaba — a decisão de novo do `exec` pergunta a confiança no editor da
  imagem nova e se quem chama ainda pede, só no fio que o gate decidiu e
  sobre um `ALLOW`; a última palavra do nascimento pergunta a do código
  que vai rodar, e só lança o comando decidido para `process.run` — e,
  desde o lote A3 do #448, só com a autoridade e um dos caminhos do
  comando —; o encerrado ouve "processo encerrado"; e as recusas sobre
  quem pede no `user.run` respondem sem a explicação do comando. Seis
  casos e as mutações de cada pergunta, todas reprovadas ([README](../README.md#decisões-pendentes),
  "A soma das cotas de processos e a cota por sessão", (f) a (l)).

  O adversário da integração `f018bee..2c39e80` — o lote A2, o #454 e o
  executor da suíte — não achou falha alta. Os pontos dele foram o lote A3
  do #448, [B]:
  - a última palavra do nascimento lança só com a autoridade do comando e
    um dos caminhos que o gate decidiu — e a mesma pergunta, sem decidir o
    comando de novo, vem também no começo do lançamento, antes de o código
    ser lido (`autorizacao::conferir_o_lancamento`);
  - o lançamento do sistema com nome único
    (`usuario::lancar_como_sistema`), protegido pela palavra; nenhum nome
    protegido com outro nome; e os carregadores só de dentro do módulo
    `usuario`;
  - o trinco do boot (`autorizacao::fechar_os_lancamentos_do_kernel`): fora
    da suíte, o kernel só lança por conta própria até lançar o servidor de
    janelas e o Terminal;
  - o NSF que passa pelos registros que não se leem;
  - o nome do editor de agora no nascimento;
  - o desfecho do `user.run` permitido que não lança.

  E o adversário do próprio lote, só de leitura, achou três baixas e seis
  informativas: oito feitas no lote — a mesma pergunta no começo do
  lançamento; as guardas do `xtask` mais fechadas, nos irmãos do
  `usuario/mod.rs`, no `include` pela palavra, no `use` montado numa
  macro, no atributo da suíte no código e no trinco logo depois dos dois
  lançamentos; a conta da suíte com o controle positivo e as duas marcas
  num atômico só; e o caso da (n) com a autoridade de outra pessoa —, e a
  nona, de antes dele, à parte. E o adversário do delta achou quatro
  contornos informativos, todos num dono, feitos também: o `use` montado
  pelos argumentos de uma macro, o apelido de um carregador no próprio
  `usuario/mod.rs`, o trinco sombreado no `main.rs` — que agora se chama
  pelo `crate::` — e a macro que tiraria o atributo da suíte do
  `executar`.

  A amarração é pela autoridade e pelo caminho, e não pela contagem: dois
  lançamentos com a autoridade do comando e o caminho decidido, dentro do
  mesmo `user.run`, passam os dois, cada um gravado como a execução da
  mesma decisão; o único chamador lança uma vez; contar seria regra nova,
  [C], não tomada. E a descrição do `user.run` diz o que o gate faz sem
  `path` (o exemplo embutido é `/bin/exemplo`). Seis casos novos, três
  reforçados, e sessenta e quatro mutações
  ([README](../README.md#decisões-pendentes), "A soma das cotas de
  processos e a cota por sessão", (m) a (z)).

  O lote A4 (#467, #466, #469 e #471), [B], fez a nona do adversário do
  lote A3 — um defeito de antes daquele lote — e três pontos ao lado dela:
  - a imagem que se lê e não se carrega é conferida antes de o fio
    nascer (`usuario::programa::conferir_a_imagem`, a conta pura do
    primeiro passo da carga, sobre os mesmos bytes que o fio carrega),
    também a do exemplo embutido: recusada, o desfecho `ERROR` com o
    motivo e `launched: false`. Antes, o fio nascia, o nascimento ia à
    auditoria como `processo N lancado`, quem pediu ouvia
    `launched: true`, e o erro ficava só no log;
  - a que não se mapeia no fio novo grava o desfecho depois do
    nascimento, em nome de quem o gate decidiu e citando a decisão, pelo
    `autorizacao::DesfechoDoLancamento`, guardado no fio do comando e
    entregue ao fio novo na carga, que o larga antes de entrar no
    programa e antes de terminar. Ele não autoriza nada, e só o
    lançamento o nomeia;
  - as recusas das perguntas sobre quem pede continuam gravadas como o
    gate as grava, e, dentro de um comando, o `ALLOW` do `user.run`
    ganha o desfecho delas, com o mesmo código e o detalhe que o gate
    gravou — abreviado, como todo detalhe acima do teto, quando a citação
    da decisão o alonga (o I1 do adversário do lote A4) —, também na cota
    contada de novo no nascimento; fora de um comando, só a do gate. É a
    alternativa (a) do plano; a (b), um registro só que
    citasse a decisão, mudaria o desenho da recusa do gate, e é [C], não
    tomada. A recusa conta uma vez no NSF — no risco, nos contadores e
    no perfil, que só contam decisões. O encerrado na última palavra já
    tinha o desfecho antes do lote A3 (o `nasce` grava a recusa como a
    execução da decisão desde o `6cea470`, e pergunta pelo encerrado
    desde o `869dc08`): o que faltava era o das perguntas do começo e o
    da cota;
  - os registros que o NSF não lê vão ao log numa linha por lote: a
    janela de 512 dava 512 linhas por volta, e o caso dela levava 72 s no
    x86 e 77 s no ARM em depuração, 138 e 149 ms por linha; agora são 8
    linhas e uns poucos segundos;
  - o `exec` da imagem que não se confere devolve
    `PROGRAMA_DESCONHECIDO` (−7), e só a memória que falta,
    `SEM_MEMORIA` (−5); antes, as duas eram −5. Nenhum documento nem
    programa dependia do −5, e a auditoria do `exec` não mudou.

  Quatro casos novos, dois reforçados, quatro testes no hospedeiro e
  vinte e quatro mutações, todas reprovadas
  ([README](../README.md#decisões-pendentes), "A soma das cotas de
  processos e a cota por sessão").

  O lote A5, [B], fez os achados do adversário do lote A4 — os quatro
  baixos, dois informativos e dois dos três de antes do lote —, sem
  autoridade, regra, registro ou semântica de auditoria novos:
  - a conferência da imagem tem teto — a tabela de segmentos de até 64
    entradas e as notas de até 4 KiB, somadas —: antes, uma imagem de
    milhares de `PT_NOTE` custava, no fio de quem lança, o quadrado do
    tamanho dela. Os tetos não são contrato: ficam muito acima dos
    programas de verdade, de três ou quatro entradas e no máximo 1044
    bytes de notas, e o `sdk-conferir` sem eles fica para um lote
    seguinte;
  - a `Carga`, o `hospedar` e o `carregar_a_carga` passaram para dentro
    de `lancar_por` — o `hospedar` voltou —, onde o compilador confere o
    alcance, e o `xtask` confere que continuam lá;
  - no NSF, a execução que cita uma decisão mais velha que o registro
    que pôs o programa de agora não o troca, nem liga aresta: o desfecho
    tardio de um `user.run` nativo voltava quem pediu ao programa de
    antes. A alternativa de gravar o desfecho sem quem pediu mudaria o
    registro, e é [C], não tomada;
  - a guarda dos nomes protegidos acusa também o `type` que nomeia um
    deles e o nome de função guardado como valor, nos donos inclusive;
  - o desfecho das recusas sobre quem pede é o detalhe do gate,
    abreviado acima do teto pela citação (o I1); e o
    `DesfechoDoLancamento` só grava o que não acontece, conferido na
    depuração (o I5);
  - a página `[TETO, TETO + 4 KiB)` de um `PT_LOAD` vazio no teto não se
    mapeia mais: toda faixa de página fica dentro de `[BASE, TETO)`;
  - as regras `TetoExercido` e `AbusoDeCredencial` procuram a palavra no
    texto do detalhe, sem o nome do programa de quem pediu.

  Dois casos novos, seis testes no hospedeiro e vinte e sete mutações
  ([README](../README.md#decisões-pendentes), "A soma das cotas de
  processos e a cota por sessão").

  O lote A6, [B], fez os achados do adversário e do revisor do lote A5 —
  os quatro baixos, os dois informativos e as observações de teste — e uma
  observação do especialista dele, sem autoridade, regra, registro ou
  semântica de auditoria novos:
  - no `usuario/mod.rs`, cada carregador e cada passo da carga só aparece
    no item das funções que o usam — o lançamento e a troca de imagem —, e
    a entrada de um fio novo, a palavra `extern`, só em `lancar_por`: o
    `xtask` confere pela estrutura, e não pelo nome. Um `const` com um
    carregador, ou um fio novo com outros nomes no nível do módulo, eram um
    segundo caminho de lançamento, sem o gate;
  - a guarda dos nomes protegidos acusa também o nome nos argumentos de
    uma macro e no corpo de uma definição, no dono inclusive, o `type`
    montado numa macro, nos donos, e o `self` renomeado de uma lista do
    `use`; e, num dono, o `use` que passa por um nome protegido e alcança
    outro arquivo — `pub(crate) use crate::autorizacao::Lancador::Kernel;`
    dava a variante aos outros sem a palavra —, com `pub`, ou sem ele num
    módulo com filhos de fora;
  - a conferência da imagem limita a soma das páginas dos segmentos a 64
    MiB, o espaço do programa no mapa do usuário: a carga do `exec`, que
    roda dentro da chamada e mascarada, zerava até quase 256 MiB. Tirar a
    carga do `exec` de dentro da chamada fica para um lote seguinte; o
    teto não é contrato, e fica muito acima dos programas de verdade;
  - no NSF, o nascimento inteiro só se lê num `ALLOW`, como o cortado: um
    `ERROR` que dissesse `processo N lancado` forjava a proveniência de N.
    O registro não muda: muda a leitura. A aresta `Executa` que o grafo liga
    ao processo que ele já esqueceu pelo teto, sem a guarda da execução de
    uma decisão de antes, fica: não é uma guarda de uma linha, e não muda a
    proveniência de ninguém;
  - a suíte confere o motivo de duas recusas da conferência que as
    mutações EL6 e PG3 mudavam sem nada reprovar, e o de cada avaria de
    `elf: recusa imagens invalidas`, com a da tabela fora da imagem.

  Dois casos novos, um reforçado, seis testes no hospedeiro e vinte e oito
  mutações, todas reprovadas ([README](../README.md#decisões-pendentes), "A
  soma das cotas de processos e a cota por sessão").

  O lote A7, [B], fez os achados do adversário do lote A6 — os cinco
  baixos e os três informativos — e o item 10 do revisor dele, sem
  autoridade, regra, registro ou semântica de auditoria novos:
  - as guardas do `xtask` fecham os desvios que compilavam e passavam:
    nenhum `impl` no item das funções da carga — o compilador não escopa
    o método de um `impl` de dentro de uma função, e um dentro de
    `lancar_por` dava o fio novo a todo o crate —, e nenhum atributo que
    exporte nos arquivos dela; no `programa.rs`, cada carregador só nas
    funções que o usam, pela mesma regra do `usuario/mod.rs`, e nenhum
    `extern` nele nem no `codigo.rs`; num dono, todo `use` no nível de um
    módulo que passa por um nome protegido, com `pub` ou sem; e o kernel
    só com os recursos instáveis da lista, sem macro 2.0, sem `${…}` e
    sem `crate-attr` no config do cargo, no `xtask` e na CI — só pelo
    texto até o lote A8, e, desde ele, também pela lista dos rustflags que o
    cargo lê;
    a macro 2.0 e o `${concat}` levavam ou montavam o nome protegido sem a
    palavra;
  - no NSF, o nascimento pelo `fork` também só se lê num `ALLOW`. O
    registro não muda: muda a leitura;
  - a guarda do `DesfechoDoLancamento` contra o código que permite vale
    nas duas compilações — era um `debug_assert!` —: com um que permite,
    o desfecho não grava, diz no log e devolve zero;
  - o caso das vagas conta as passadas do outro coletor da partida à
    parada, e as duas diferenças de `nao_carrega` têm cada uma a mensagem
    dela.

  A desmontagem do espaço anterior dentro da chamada do `exec`, que o
  teto das páginas não limita, foi medida — no emulador, com 240 MiB
  mapeados, de 22 a 36 ms em release e de 273 a 417 ms em depuração, com
  as interrupções mascaradas; com mais de um núcleo, um que não espere a
  trava da paginação anda o relógio, e ele não perde nada — na medida, os
  outros estavam livres; se todos a esperam, mascarados, perdem como um só
  (o I-1 do adversário do lote A7) —, e com um só perde um tique em release
  — e fica com a carga do `exec`, para um lote seguinte. Um caso novo,
  cinco reforçados, dez testes no hospedeiro e dezenove mutações, todas
  reprovadas, com cinco de antes rodadas de novo
  ([README](../README.md#decisões-pendentes), "A soma das cotas de
  processos e a cota por sessão").

  A carga da imagem no teto, medida junto, custava no aarch64 com quatro
  núcleos, em release, 1,85 s contra 0,21 com um, no emulador: eram os
  `tlbi` difundidos de cada troca de entrada, e dois em cada três eram os
  que o `mapear_frame` fazia a cada página nova, e que a arquitetura não
  pede — uma entrada inválida não está em TLB nenhuma. Sem eles (o
  trabalho arm-tlbi, [B]), a mesma carga leva de 0,51 a 0,78 s, com os da
  remoção, que ficam, e o `mapear` cheio, de 1,9 a 2,0 s, passa a
  0,17–0,21 s ([README](../README.md#vários-núcleos), "A entrada nova não
  pede `tlbi`").

  O lote A8, [B], fez os achados do adversário do lote A7 — os sete baixos
  e os três informativos — e fechou as guardas de texto do `xtask` por
  inventário, sem autoridade, regra, registro ou semântica de auditoria
  novos. Três adversários seguidos acharam formas novas de levar um nome
  protegido, ou a carga de um programa, para fora do lugar, sem que o texto
  as visse — uma macro de fora, um `impl` de dentro, um recurso instável,
  um `path` montado, um pacote de macros procedurais, um escape no config
  do cargo —, e todas de quem escreve código no kernel, e não de um
  processo. Uma guarda de texto nunca fecha tudo o que o compilador aceita:
  ela acusa o desvio acidental e o ingênuo, e as formas que o inventário
  cobre; o resto fica com a revisão e com a política de desenvolvimento
  ([README](../README.md#as-guardas-de-texto-o-que-elas-cobrem), com o
  modelo de ameaça e o inventário). As guardas novas:
  - no item das funções da carga, só as macros de uma lista fechada, pelo
    caminho, cujo nome nenhum arquivo do kernel redefine nem traz de fora;
    e nos arquivos da carga, nem montador nem ligador — uma macro de fora
    escrevia ali o `impl` ou o `#[no_mangle]`, e o `.globl` de um `asm!`
    daria um símbolo a uma entrada de dentro (o `asm!` de linha passou no
    `cargo check`, que não monta nem liga);
  - fora do módulo `usuario`, nenhum carregador nos tokens de uma macro;
    e o atributo com `$` fora do `doc` se acusa, porque o `cfg_attr` monta
    o `path` também;
  - as dependências do kernel pelo grafo do cargo: as diretas e os pacotes
    de macros procedurais do grafo em listas fechadas, só o crates.io e o
    repositório, o kernel sem `build.rs`, e os pacotes do repositório sem
    `build.rs`, macro exportada, recurso instável nem `include`;
  - o config do cargo como o cargo o lê: os rustflags de cada alvo, os da
    lista, sem ligador, `build.rustflags`, `[unstable]`, `[env]` nem
    rustflags de perfil — o resto das tabelas, só desde o lote A9 —; o
    `Cargo.toml` do kernel sem `cargo-features`, `rustflags` nem escape; e
    nenhum `RUSTFLAGS` na CI;
  - o embrulho da suíte do desfecho é nome protegido, e a guarda do
    desfecho tem um caso também dentro de um comando.

  A carga da imagem no teto dentro do `exec`, mascarada — de 0,12 a 3,0 s
  no emulador, conforme a arquitetura, o perfil e os núcleos (os números no
  [README](../README.md#decisões-pendentes), "A soma das cotas de processos
  e a cota por sessão") —, continua com a desmontagem, para um lote
  seguinte. Um caso novo na suíte, dezesseis testes novos no hospedeiro e um
  ajustado, e as mutações do lote, todas reprovadas.

  O lote A9, [B], fez os achados do adversário do lote A8 — o alto, os sete
  médios, os quatro baixos e o I2 dos informativos — e os do revisor dele,
  sem autoridade, regra, registro ou semântica de auditoria novos. O
  inventário das guardas de texto não fechava: faltavam fontes — o executor
  do `cargo xtask`, a raiz do crate, o módulo da suíte, o `[source]`, o
  ligador do hospedeiro, a feature padrão, o ambiente da CI, a linha de
  comando do `xtask` —, e formas passavam pela guarda de uma fonte listada —
  a macro de nome cru, o que as macros da lista expandem, o `#$a`, a marca
  de direção. Cada guarda nova fecha a fonte, e não a forma do ataque:
  - o executor e o apelido do cargo, fora do cargo: o `cargo xtask` é o
    `cargo run` do `xtask`, e um executor no config da raiz que
    respondesse `invariantes` com sucesso fazia o passo das invariantes da
    CI passar sem guarda nenhuma. A ação que confere o compilador ganhou o
    passo do executor, antes de todo `cargo` da CI — pela consulta do
    próprio cargo, o `[alias]` só o oficial e nenhuma tabela `target` com
    executor nem ligador em todo diretório de build, a raiz só com o
    apelido, e nenhum
    `CARGO_ALIAS_*`, `CARGO_TARGET_*_RUNNER` nem `_LINKER` no ambiente —; o
    `xtask` vê, no começo de todo comando, o executor e o apelido que ainda
    o chamam; e as `CARGO_BUILD_RUSTC*` do ambiente, que a consulta da
    tabela `[build]` não soma, entraram entre as variáveis que trocam o
    compilador;
  - a macro de nome cru de uma palavra-chave é uma invocação; os três
    registros do log chamam o `::core::format_args!`, que nenhum item do
    módulo sombreia, e têm o corpo da lista do `xtask`, token a token; o
    `core` e o `alloc` que as macros da lista chamam são os de verdade —
    nenhum `as core` nem `as alloc`, que na raiz do crate trocariam o
    pacote, e nenhuma dependência do kernel renomeada —; e o `#` que não
    abre um atributo é um atributo montado por uma macro;
  - a raiz do crate pelo grafo do cargo — o binário do kernel em
    `kernel/src/main.rs`, a biblioteca de cada pacote do repositório no
    `src/` dele —, as features do kernel numa lista fechada, sem uma
    padrão, e a suíte só na compilação de teste, pelo módulo da raiz do
    crate;
  - o config do cargo do kernel com a tabela `target` só nas dos dois
    alvos dele — o ligador do hospedeiro e o de um `cfg(…)`, que o cargo do
    canal lê, rodavam na compilação do kernel —, sem `[source]`, `[patch]`,
    `[host]` nem `[profile]`; a CI só com as variáveis do cargo de uma
    lista; o `xtask` só com o ambiente de uma lista nos processos que roda,
    sem `--config`, `-Z`, `cargo rustc` nem `cargo rustdoc`; e a marca de
    direção como espaço, como o `rustc` a lê;
  - o caso do desfecho dentro de um comando confere que o gancho rodou
    dentro dele: um `ERROR` pelo caminho que só grava num comando, que sai
    como a execução do `user.run` do caso.

  Fica o que o inventário diz em cada linha, e o código do repositório que
  roda no job dos lints antes do passo das invariantes — os testes do
  hospedeiro, os `build.rs` —, que pode mudar a árvore que ele lê, como pode
  mudar o próprio `xtask`: fica com a revisão
  ([README](../README.md#as-guardas-de-texto-o-que-elas-cobrem)). Um caso
  reforçado na suíte, vinte e dois testes novos no hospedeiro — treze do
  adversário, quatro deles adaptados à guarda que fecha a fonte — e três
  reforçados, e as mutações do lote, todas reprovadas.

  Depois do lote A9, o lote ICACHE, [B], fez os achados do adversário do
  trabalho arm-tlbi — menos um ponto fraco do caso da marca, que ficou para
  o lote ICACHE-2: um `tlbi` difundido de um terceiro núcleo, entre as duas
  escritas do outro, mascararia a M5 —, sem autoridade, regra, registro,
  identidade ou persistência novos:
  - a carga de código no aarch64 sincroniza o cache de instruções antes de
    uma página escrita pelo kernel ficar executável — `dc cvau` e `ic ivau`
    em cada linha, com as linhas do `CTR_EL0` (as menores de todos os
    núcleos) e as barreiras, e sem a parte que o `IDC` ou o `DIC` dispensam
    (`arch::sincronizar_instrucoes`; no x86, nada). Num processador que não
    anuncia os dois — o Cortex-A72 que a CI emula —, um processo podia
    executar, de um frame recém-devolvido, o código do dono anterior, com a
    autoridade do novo. A carga é o único caminho por onde o kernel escreve
    código: o `fork` divide os frames, e a cópia na escrita nunca copia uma
    página executável — só marca as graváveis, e o `elf::validar` recusa o
    segmento gravável e executável. O emulador não mostra a falta —
    tirada a manutenção, só o caso da conta reprova; o QEMU sem aceleração
    mantém o código traduzido coerente com a memória —, e o caso confere a
    manutenção pela conta das operações;
  - o `mapear_frame` volta ao `tlbi` difundido na entrada compartilhada —
    as regiões do kernel e a raiz do kernel —, contra a falta de tradução
    espúria de um núcleo sem o FEAT_ETS (citado sem conferir no manual) que
    lê uma página do kernel logo depois de um aviso (fatal no EL1), e mantém
    o `publicar` na entrada privada de um processo, onde está o ganho medido
    do trabalho arm-tlbi. Medido de novo, antes e depois, pelo mesmo
    instrumento — no emulador, em release; outro que o de cima, e não
    comparável a ele um a um —: a carga da imagem no teto com quatro
    núcleos, de 335 a 876 ms antes e de 616 a 818 depois, e o `mapear`
    cheio, de 141 a 210 ms e de 138 a 194 — o ganho fica;
  - as tabelas esvaziadas voltam ao alocador depois da invalidação: no ARM,
    depois do `vmalle1is`, na remoção e na desmontagem do espaço; no x86,
    depois de um `invlpg` que vem depois da limpeza;
  - o caso da marca da cópia na escrita conta as resoluções e as cópias do
    próprio espaço, e não as da máquina; e a remoção numa página privada,
    no mesmo núcleo, ganhou caso (o A1 do adversário).

  O que nenhum caso mostra no emulador — o cache de instruções, a falta
  espúria e a cache dos níveis intermediários — fica no "O que fica de
  fora" de [Vários núcleos](../README.md#vários-núcleos), com as entradas de
  topo das regiões do kernel, conferidas sem defeito (o item G).

  O lote ICACHE-2, [B], fez os achados do adversário e do revisor do lote
  ICACHE, sem autoridade, regra, registro, identidade ou persistência
  novos:
  - o caso da carga tira o que espera do `CTR_EL0` que ele mesmo lê em
    cada núcleo ligado, e não da função que a carga usa — com o `IDC` e o
    `DIC` lidos ao contrário nela, o A72 não fazia manutenção nenhuma, e o
    caso esperava zero —, e confere a faixa que a sincronia percorreu, que
    o emulador não mostra nem como falha;
  - as metades do caso da marca, e o caso da remoção no aarch64, repetem a
    rodada em que um núcleo de fora do par difundiu um `tlbi` na janela, até
    uma limpa, e reprovam sem nenhuma; e o caso da remoção, no x86,
    remapeia sem o `invlpg` que cobria a remoção sem o dela;
  - no x86, a tabela de página nova chega zerada ao pacote `x86_64`, que a
    liga antes de zerá-la — de antes do lote ICACHE: entre a ligação e o
    zerar, um percurso de tabela leria o que o frame tinha, uma tabela
    velha com as entradas presentes —; um caso novo confere, com um frame
    sujo encomendado ao alocador, que nenhuma tabela nova chega suja a quem
    a liga, nas duas arquiteturas;
  - o texto: a mutação do x86 que passava não era equivalente, e as
    citações que vieram de memória — o manual da Arm, o FEAT_ETS, os
    manuais da Intel e da AMD, o QEMU — estão marcadas como tais
    ([README](../README.md#vários-núcleos), "Os casos do lote ICACHE veem o
    que dizem conferir" e "A tabela nova chega zerada a quem a liga").

  O lote A10, [B], fez os achados do adversário do lote A9 — os dois altos,
  os dois médios, as cinco baixas e as seis informativas —, os do revisor
  dele e um achado dele mesmo, sem autoridade, regra, registro ou
  semântica de auditoria novos. A guarda "fora do cargo" do lote A9, o
  passo do executor da ação do compilador, confiava no `cargo` que
  resolvia e lia o ambiente do job por três nomes: um
  `rust-toolchain.toml` com `path` num diretório de build fazia a própria
  ação rodar um "cargo" do repositório, que plantava um
  executor no config do `CARGO_HOME` (o F2); e o `RUSTFLAGS` do job trocava
  o ligador do binário do `xtask` das invariantes, e o `RUSTDOC` e o
  `RUSTFMT` rodavam um programa do repositório antes delas (o F1). A raiz
  da confiança é a definição da CI — os workflows e as ações —, e quem a
  protege é a revisão; abaixo dela, a ação garante que o primeiro `cargo`
  que roda o código do repositório nas invariantes é o do toolchain
  oficial, no ambiente conferido, sem nada do repositório antes:
  - o passo do ambiente, em Python — o do sistema, e não o do PATH —, antes
    de qualquer programa do toolchain: o ambiente do job por uma lista
    fechada dos nomes que o cargo, o rustc, o rustdoc, o rustfmt e o rustup
    leem; as casas do cargo e do rustup e o PATH fora do repositório, e o
    `cargo` e o `rustc` do PATH os proxies do rustup; nenhum
    `rust-toolchain` fora dos dois oficiais, e os dois só com as chaves do
    oficial; nenhum arquivo do commit num diretório de saída do cargo. E
    todo `cargo` da ação no toolchain fixado pelo canal, e não no que o
    diretório escolhe;
  - as invariantes como o último passo da ação, que só o job de lints
    liga: antes do cache e de todo outro `cargo` do job — a formatação, os
    testes do hospedeiro e o clippy rodam código do repositório —, no
    ambiente que a ação conferiu (o IN3);
  - o config de cada diretório de build fechado ao que os configs do
    repositório usam — o apelido, o alvo e os rustflags nas formas de hoje
    —, na ação e no `xtask`: o `[env] PATH`, o `[host] linker` e os
    rustflags que escolhem o ligador, por qualquer opção, se recusam (o
    F3); e o `paths` no config do kernel (o J);
  - no `xtask`, o `RUSTDOC`, o `CARGO_BUILD_RUSTDOC` e o `build.rustdoc`
    como desvios do compilador (o IN6); nos workflows, nenhum `RUSTDOC`,
    `RUSTFMT`, `PATH` nem `__CARGO*`, e o `RUSTDOCFLAGS` só no passo da
    documentação (o F1 e o IN4); nenhum `mod` nos tokens de uma macro, por
    onde o `#[path]` montado alcança um arquivo (o I); a biblioteca de cada
    dependência direta do kernel com o nome do pacote, nenhuma com o de um
    pacote do sysroot (o G); e a linha de comando do `xtask` sem `set_var`,
    com os escapes resolvidos e sem `sh -c` com o cargo (o H);
  - a conferência da ação lê cada diretório de build como um item da tupla
    — a raiz também (o E5 do revisor) —, e o teste que roda a ação, com o
    proxy do rustup no PATH, como no runner, monta um executor em cada um
    (a M1);
  - o caso do desfecho dentro de um comando confere que o controle do
    gancho é o do `user.run` do caso, pela decisão que ele cita (o IN1);
  - o achado do lote: o `profile-rustflags` de um manifesto — o
    `cargo-features` e os `rustflags` de um perfil — fazia o cargo do
    canal ligar o `xtask` das invariantes com um programa do repositório;
    o passo do ambiente recusa o `cargo-features` em todo manifesto, e os
    `rustflags` e o `codegen-backend` em todo perfil.

  Fica a definição da CI, com a revisão — um passo novo, o `env:` de um
  passo, o script da ação —; as variáveis genéricas do processo, como o
  `LD_PRELOAD`, que só ela põe; o código do próprio `xtask`, que é o
  conferente; e o config pessoal do `CARGO_HOME` de quem compila, que vira
  desvio ([README](../README.md#as-guardas-de-texto-o-que-elas-cobrem)). Um
  caso reforçado na suíte, dezesseis testes novos no hospedeiro — seis do
  adversário, dois deles adaptados ao arnês que roda a ação como no runner
  —, dois reescritos e cinco reforçados, e as mutações do lote (*As do lote
  A10*, no [README](../README.md#as-mutações-do-ponto-sem-volta-e-de-quem-pede)).

### I7

**O resumo sem chave dos parâmetros, no console sem ninguém** — o I7 da
pendência #298: o resto do N6.

- **O problema.** Num console sem ninguém entrado, todo comando é recusado
  (`DENY_NOT_AUTHENTICATED`) e gravado. O N6 (`75444ef`) tirou o texto da
  linha que não é comando — ela vai à auditoria com o marcador `(comando
  desconhecido)`, sem resumo —; o comando que existe continua com o nome e
  o resumo dos parâmetros, o BLAKE2s sem chave de
  `politica::auditoria::resumo_dos_parametros`, que quem lê a auditoria
  adivinha por dicionário. O que se digita depois do nome de um comando —
  uma senha no lugar errado também — vai assim à auditoria e ao journal
  ([Consoles](../README.md#consoles); `kernel/src/interpretador.rs`,
  `despachar`).
- **O que se faz.** A (b) da pendência: o comando que existe, sem ninguém
  entrado, gravado sem o resumo, como a linha que não é comando — a regra
  de que a senha não vai à auditoria, que o N6 aplicou como [B]
  (README.md:5115-5120). Antes do login, a decisão e o registro não mudam
  com o parâmetro, nem com a presença dele.
- **O que não se propõe.** A (c), **(minha)**, um resumo com chave — um
  MAC com uma chave derivada da do Duke —: uma chave nova, e a custódia
  dela, seria [C].
- **O estado.** Feito, no lote B do #448: `autorizacao::recusar_sem_login`
  não recebe mais os parâmetros, e todo registro de quem não entrou leva o
  resumo do vazio — o tipo impede um caminho sem login de gravar um
  resumo. O caso `consoles: sem ninguem, o comando vai a auditoria sem o
  resumo dos parametros; com alguem, com ele` digita o mesmo comando com
  parâmetros diferentes, e com uma senha depois do nome, e confere o mesmo
  registro, sem o resumo do que se digitou.

  No lote B2, a troca da própria senha entrou na regra. Antes, `senha` com
  algo na linha, sem ninguém entrado, era recusado no console, sem
  registro e com uma resposta própria, e `senha` sozinho gravava: o
  registro mudava com a presença do parâmetro — não com o valor, e não era
  um oráculo. Agora a pergunta de quem está entrado vem antes da
  conferência da linha (`interpretador::comecar_troca`): os dois são a
  mesma recusa, o mesmo registro e a mesma resposta, e o que veio junto
  não vai a lugar nenhum (o caso `consoles: sem ninguem, a senha com algo
  na linha e a mesma recusa da senha sozinha`). Com alguém entrado, a
  linha é conferida antes de qualquer decisão, como antes. Sobra o
  `logout` sem ninguém, que só diz que ninguém entrou, sem registro: não
  há sessão a encerrar, e nada do que veio junto é lido.

### A9-RESUMO

**O tamanho do resumo na descrição de um programa** — o achado 9 do
adversário do passo 1.

- **O problema.** A auditoria e o NSF nomeiam um programa pelo nome, pelos
  8 dígitos hexadecimais do começo do BLAKE2s do executável — 32 bits — e
  pelo editor: com o mesmo nome e o mesmo editor, dois executáveis com os
  mesmos quatro primeiros bytes do resumo têm a mesma descrição — uma
  segunda pré-imagem de uns 2^32 resumos ([README, Decisões
  pendentes](../README.md#decisões-pendentes); [SEGURANCA, O modelo de
  evento](SEGURANCA.md#o-modelo-de-evento)).
- **O que se faz.** O resumo de 16 dígitos, 64 bits. O texto do detalhe
  da auditoria não é contrato (SDK.md:88-93). Mudam junto: o
  `resumo_e_editor` (`politica/src/auditoria.rs`), que só reconhecia
  um resumo de 8 dígitos, e é por onde o NSF lê o resumo e o editor de uma
  descrição (`seguranca/src/grafo.rs`, `o_mesmo_programa`); e a conta do
  teto de 96 bytes, medida — a descrição já
  encolhe o nome e o editor antes do motivo. As descrições já gravadas, de
  8 dígitos, ficam no journal da auditoria: o leitor continua a
  reconhecê-las. Este dossiê concorda com a classificação: a descrição diz
  a mesma coisa, com mais bits.
- **O estado.** Feito, no lote B do #448:
  - a largura mora em `politica::auditoria` (`DIGITOS_DO_RESUMO`,
    `comeco_do_resumo`), e o kernel a usa na descrição e no nascimento;
  - o leitor (`forma_do_resumo`, dentro de `resumo_e_editor`) aceita 8 e
    16 dígitos;
  - o NSF compara dois resumos do mesmo tamanho inteiros, e um de 8 com um
    de 16 pelos 8 do começo — o que o de 8 diz (`o_mesmo_resumo`): o par
    misturado só se forma com o journal de antes lido sem o `policy.load`
    do boot seguinte;
  - o teto, medido ("O pior caso, medido", em
    `politica::auditoria::detalhe_composto`): o detalhe cabe sempre, e o
    que encolhe é o texto, 8 bytes antes — o motivo de toda falta da
    procedência fica reconhecido enquanto os dígitos do fio e da decisão
    somam até 20 (eram 28), e mais registros abreviam o nome do programa
    (`(? <resumo>`).

  O adversário do lote achou duas consequências, corrigidas no lote B2:
  - o registro do firewall, que o NSF reconhecia pelo número da regra no
    fim do texto, perde o número antes: o NSF deixava de ver o bloqueio com
    os números grandes. Agora ele lê também o bloqueio cortado
    (`seguranca::evento`, `Tipo::Firewall { regra: None }`): a execução de
    `net.connect`, `net.send` ou `net.recv` com `DENY_POLICY` e a decisão
    citada, com o texto cortado no começo de `bloqueado pelo firewall,
    regra `, ou só a marca. Sem o número, o risco e o contorno do firewall
    não mudam — os dois contam destinos —, e a proveniência diz
    `firewall_blocked` em todo fluxo barrado, e o `firewall_rule` só quando
    algum registro do fluxo guardou o número. Pela mesma conta, o
    nascimento cortado (`processo N ?`) é reconhecido até os dígitos do
    filho, do fio e da decisão somarem 33, no pior caso — o processo de
    fora com o nome e o editor longos;
  - a descrição inteira de 8 dígitos seguida da inteira de 16 do mesmo
    executável ainda virava uma troca no grafo. Agora o processo fica com
    a de 16, sem aresta (`seguranca::grafo`).

  Fica de fora, para um próximo lote [B] do mesmo tipo, o atestado do
  enlace (`pela relacao <8>, atestado <8>`), que vai à auditoria com 32
  bits.

### DN-4

**O handoff como o próximo marco da fase 15** — o DN-4 do relatório da
continuidade.

- **O que se faz.** O roteiro já põe o handoff primeiro entre os marcos
  que faltam — "O handoff, os recursos remotos, a presença, a continuidade
  e os pacotes são os marcos seguintes" ([Roteiro](../README.md#roteiro),
  fase 15; README.md:12840-12842) —, e escolher a próxima tarefa dentro
  do roteiro é do coordenador
  ([5.1](../CLAUDE.md#51-o-que-o-coordenador-decide-sozinho),
  [5.2](../CLAUDE.md#52-a-continuidade)). As decisões do marco — a DH-1, a
  DH-2 e a DH-3 — continuam do dono: a [R15-HANDOFF](#r15-handoff).
- **O estado.** Decidido pelo roteiro.

### SDK-CANAL

**O canal sem nome** — a **DC-1′** do relatório da continuidade: o resto
do R6 do DN-3, a tomada dos nomes do laço.

- **O problema.** O `Laco::novo` tenta 16 nomes previsíveis
  (`laco-<id>`, `laco-<id>-1`…); quem os tomar todos — 8 processos de uma
  sessão de operador, com 2 canais cada — impede o laço daquele processo.
  `escutar` não reserva nome nem passa pelo gate: a mesma raiz dos nomes
  `terminal` e `janelas` da [DT-1](#dt-1) ([SDK, Limites
  conhecidos](SDK.md#limites-conhecidos)).
- **O que se faz.** A recomendação do relatório: **opcional; deixar
  documentado até um consumidor pedir.** Quando vier, o canal sem nome — o
  kernel dá a chave, sem um nome que outro tome — é crescimento do
  contrato v2, que o DS-2 faz pela lista conferida, e não muda quem decide
  nem o que se autoriza. A reserva dos nomes da DT-1 é outra coisa, e não
  depende dele.
- **O estado.** Documentado, até um consumidor pedir.

### R12-IC-NOS

**Os nós da rede principal pela árvore de estado** ([ICP, O que fica de
fora](ICP.md#o-que-fica-de-fora)).

- **O problema.** `icp-api.io` é servido por nós que giram — quatro
  endereços em pouco mais de uma hora. A política enumera os IPv4 que o
  pré-voo viu; quando a máquina recebe outro, o gate recusa, e a fumaça
  real falha fechada. O ICP diz que descobrir os nós pela árvore de estado
  (`api_boundary_nodes`) "seria uma decisão nova".
- **O que se faz.** A (b), **(minha)**: o programa descobre os nós pela
  árvore de estado, e o administrador os escreve na política pelo
  `policy.write`, com prova — a ferramenta muda; a política, o gate e a
  fonte da decisão, não.
- **O que não se propõe.** A (c), **(minha)**: a política aceitar os
  destinos que a raiz do IC certifica — uma fonte nova de destino, que
  esbarra na Policy como fonte da decisão: [C].
- **O estado.** No roteiro da fase 12, quando houver um consumidor.

## As fechadas que não se reabrem

O que é CLOSED e toca nestes assuntos. Nenhuma entrada deste dossiê as
propõe de novo; quando uma esbarra numa delas, a fechada é restrição.

- **As invariantes** ([1.7](../CLAUDE.md#17-as-invariantes-permanentes)):
  nenhuma ABI do Linux; a Pessoa como identidade durável; a autoridade
  carregada pelo processo; o processo como endpoint; system/root como
  autoridade máxima, sem curinga; as permissões enumeradas, sem
  `ALLOW(*)`; um Gate, uma cadeia de autorização, nenhuma autorização
  paralela, e toda operação passa pelo Gate; a Policy como fonte da
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
  revisada, um nome nunca muda de sentido, e remover é só numa versão
  maior; a forma binária do programa — o ELF dos dois alvos — também é
  contrato.
- **A C1** (11/11/2026,
  [PERSISTENCIA](PERSISTENCIA.md#os-leitores-e-o-anexar-a-trava-do-gate-sem-o-alocador)):
  o elo BLAKE2s da auditoria fica com a trava — sem protocolo otimista, sem
  lotes, sem árvore de Merkle. Volta a ser considerada só se uma medida
  mostrar o elo como gargalo relevante.
- **A 14.1** (alternativa A, 7/11/2026) **e a alternativa 1 do A1**
  (8/11/2026) ([Coordenação](../README.md#coordenação)): a cota conta os
  zumbis e os mortos até o recolhimento. Que só o coletor recolhe é o que
  está feito, e não uma decisão: as alternativas não adotadas do A1
  ficaram registradas, "nenhuma descartada" (README.md:5236-5246) — a (2),
  as vagas reservadas aos fios do kernel, também uma das três da 14.1
  (README.md:8743-8746), segue aberta na [COTA-SOMA](#cota-soma); a (3) é
  uma mitigação [B]; a (4), investigada, não entrou.
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
