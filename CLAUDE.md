# Duke OS — como o desenvolvimento é feito

Este arquivo é lido no começo de toda sessão de desenvolvimento neste
repositório e é **permanente**: vale para todo trabalho futuro do Duke OS,
não para um marco só. A política da seção 1 foi adotada pelo dono do
projeto em 2 de novembro de 2026, para todo trabalho de implementação —
novos DN, fases, subsistemas, kernel, drivers, sistema de arquivos, rede,
Fabric, SDK, aplicações nativas, interface, segurança, criptografia,
testes, mutações, concorrência, auditoria, documentação, ferramentas, CI,
bancadas, integração, validação entre arquiteturas, correções,
regressões, hardening, análise de segurança e qualquer outro trabalho.

## 1. A política permanente de desenvolvimento multiagente

### 1.1 O modelo

```
                AGENTE COORDENADOR
                       │
      ┌────────────────┼────────────────┐
   AGENTE A         AGENTE B         AGENTE C      (quantos o trabalho pedir)
   tarefa A         tarefa B         tarefa C
      └────────────────┼────────────────┘
                INTEGRAÇÃO ÚNICA
                       │
                TESTES COMPLETOS
                       │
                VALIDAÇÃO FINAL
```

- Use múltiplos agentes sempre que isso trouxer ganho real de velocidade,
  cobertura, qualidade ou segurança. Use um agente só quando o trabalho
  for pequeno, indivisível ou estritamente sequencial.
- O número de agentes não é fixo: 1, 2, 3, 5 ou mais, conforme o
  paralelismo real e seguro. Nunca crie agentes só para aumentar a conta.
- Paraleliza-se **trabalho**, nunca **decisões arquiteturais**
  incompatíveis.
- Os agentes podem ser muitos. A arquitetura, a linha de desenvolvimento,
  o Gate, a Policy, a cadeia de identidade e a auditoria continuam sendo
  **uma só** cada.

### 1.2 Antes de distribuir: a análise do coordenador

Para todo trabalho, o coordenador determina primeiro:

1. o que pode ser paralelizado;
2. o que depende de outra tarefa;
3. o que precisa permanecer sequencial;
4. quais tarefas são de implementação;
5. quais são de teste;
6. quais são de segurança;
7. quais são de documentação;
8. quais podem ser executadas independentemente;
9. quais alterações podem entrar em conflito — os mesmos arquivos, o
   mesmo diretório de build, a mesma CPU (ver 3.3).

Só depois distribui. Se há `A → B → C`, B espera a interface ou a
decisão de que precisa de A, e C espera B quando depende de B — nada de
paralelismo artificial. Tarefas independentes (por exemplo segurança,
sistema de arquivos, documentação e testes de partes diferentes) correm
ao mesmo tempo.

### 1.3 O coordenador

É responsável por: conhecer o estado completo do Duke OS, as decisões
fechadas, as invariantes e as dependências; distribuir as tarefas;
acompanhar os agentes; revisar os resultados; integrar as alterações;
resolver conflitos; detectar regressões; executar a validação global;
impedir deriva arquitetural; consolidar a documentação; produzir o
relatório final.

O coordenador é só uma função do processo de desenvolvimento. Ele **não**
cria autoridade nenhuma dentro do Duke OS.

### 1.4 Os agentes especialistas

Cada agente recebe uma responsabilidade claramente definida, num pedido
autossuficiente (o agente começa sem o contexto do coordenador): o
escopo, os arquivos, as decisões que se aplicam, as invariantes, o que
não fazer e o que devolver. O agente:

- lê o código relacionado e as especificações relevantes;
- identifica as dependências e entende as decisões já fechadas;
- implementa o seu escopo;
- cria testes, testa as recusas, a concorrência quando couber, e roda
  mutações quando couber;
- documenta;
- relata os problemas e corrige os que achar no seu escopo;
- devolve o trabalho ao coordenador.

Não inventa arquitetura fora do escopo autorizado.

### 1.5 Segurança: o agente adversário

Sempre que possível, um agente dedicado tenta **quebrar** o que os outros
produziram. Ele procura: bypass do Gate; bypass da Policy; autoridade
implícita; wildcard de root; confusão entre identidade e sessão; confusão
entre recurso e autoridade; falhas de revogação; replay; corridas; falhas
de isolamento; estado inconsistente; falhas de persistência, de
auditoria, de autenticação e de autorização; violações de escopo; falhas
de concorrência; qualquer mecanismo que possa criar uma segunda cadeia de
autoridade.

O adversário testa o sistema existente. Ele **não** cria um sistema de
segurança paralelo.

### 1.6 As decisões: [A], [B], [C]

- **[A] arquitetura já existente** — usa-se normalmente.
- **[B] escolha interna de implementação** — nomes internos, módulos,
  estruturas, refatorações, organização dos testes, mecanismos
  equivalentes: o agente decide sozinho. Não se pede autorização para
  decisão puramente interna.
- **[C] nova decisão arquitetural ou mudança de semântica de segurança**
  (a redação da diretriz de continuidade do usuário, de 4/11/2026) —
  exige aprovação explícita do usuário antes da implementação; um
  relatório, uma especificação ou uma recomendação não são aprovação.
  Nunca inventada em silêncio. Pare só naquele ponto e: explique o
  problema; apresente as alternativas; as vantagens; os riscos; o
  impacto; recomende uma solução; aguarde a decisão. O trabalho que não
  depende dela continua.

Nenhum agente reabre uma decisão fechada (CLOSED) só porque achou uma
alternativa tecnicamente interessante.

### 1.7 As invariantes permanentes

Todo agente, em qualquer tarefa, preserva:

- nenhuma ABI do Linux;
- a Pessoa como identidade durável;
- a autoridade carregada pelo processo; o processo como endpoint;
- system/root como autoridade máxima, **sem** wildcard implícito;
- permissões explicitamente enumeradas — nenhum `ALLOW(*)` implícito;
- um único Gate; uma única cadeia de autorização; nenhuma autorização
  paralela; toda operação passa pelo Gate;
- a Policy como fonte da decisão;
- a auditoria e a proveniência existentes;
- a Fabric como infraestrutura, nunca como autoridade; fluxos nunca
  concedem autoridade; avisos (DS-1) só sinalizam;
- o Noise nunca substitui autorização;
- a identidade própria de cada dispositivo — nenhuma identidade clonada
  ou migrada;
- a custódia das chaves — nenhuma chave exportada;
- as decisões fechadas: B1–B5; ICP-5; D1–D10 (`docs/ENLACE.md`); o
  Estágio 1; DN-1 e D8 (`docs/PAREAMENTO.md`); DN-2 com DF-1 a DF-6
  (`docs/FLUXOS.md`); DN-3 com DS-1 e DS-2 (`docs/SDK.md`); e as demais
  marcadas CLOSED no README e em `docs/`.

### 1.8 Uma linha só de desenvolvimento

- O ramo oficial é o ramo de desenvolvimento em uso quando esta política
  foi adotada: **`claude/modest-pascal-vy8p8k`**. Toda sessão continua a
  partir da ponta dele. Se a ferramenta de uma sessão designar outro nome
  de ramo, ele parte da ponta da linha oficial e continua a mesma
  história — nunca uma linha paralela a partir de um ponto antigo.
- Nenhum ramo para bug, correção, teste, mutação, regressão, concorrência,
  documentação, experimento, ajuste ou hardening; nenhum ramo permanente
  por agente ou por correção.
- Isolamento físico, quando agentes escrevem ao mesmo tempo: uma worktree
  (ou cópia) **temporária** por agente. O coordenador traz o resultado de
  volta para a linha oficial (cherry-pick ou patch, revisado), e a
  worktree e o ramo temporário dela são apagados. Só o ramo oficial é
  publicado.
- A sequência é contínua, tudo no mesmo ramo: implementação → teste →
  problema → correção → teste de novo → novo problema → correção →
  validação → continuação.
- Commits semanticamente organizados, todos na mesma linha, com o texto
  em português: `feat:` (implementa), `test:` (testes), `fix:`
  (correção), `hardening:` (fortalece), `docs:` (documentação) — e
  `ci:` ou `refactor:` quando couber. Não se cria ramo para separar tipos
  de commit.

### 1.9 As correções

Correção é desenvolvimento normal, não uma fase nova. Quando qualquer
agente acha um problema: identifica; explica a causa; corrige; testa;
testa a regressão; atualiza a documentação quando necessário; continua no
mesmo ramo.

### 1.10 Os testes

Quando se aplicam: unidade; integração; ponta a ponta; concorrência;
stress; mutações; recusas; revogação; suspensão; replay; queda (crash) e
corte de energia; persistência; recuperação; as duas arquiteturas
(x86_64 e aarch64); debug e release; virtio; bancadas; regressão. Uma
implementação não está pronta só porque o caminho feliz funciona.

### 1.11 A validação final

Antes de dar qualquer trabalho por concluído:

1. integrar as alterações;
2. resolver os conflitos;
3. executar os testes;
4. executar a regressão;
5. executar as mutações;
6. executar os testes de concorrência;
7. executar nas duas arquiteturas, quando couber;
8. revisar a segurança;
9. revisar a auditoria;
10. revisar as invariantes;
11. conferir que nenhuma decisão CLOSED foi reaberta;
12. conferir que não surgiu uma segunda autoridade;
13. nem um segundo Gate;
14. nem uma segunda Policy;
15. nem um segundo sistema de identidade;
16. conferir a documentação;
17. executar a CI completa — verde no último commit.

### 1.12 O relatório de cada grande trabalho

Estado inicial; tarefas distribuídas; agentes envolvidos; dependências;
implementação; correções; testes; mutações; problemas encontrados;
soluções; conflitos de integração; validação de segurança; CI; commit
final; decisões utilizadas; novas decisões, se houver; decisões que
continuam CLOSED; próximos trabalhos.

## 2. Os papéis prontos

Em `.claude/agents/`, cada um com as regras desta política no próprio
pedido:

| Papel | Para quê |
|---|---|
| `duke-especialista` | implementa um escopo definido (código, testes, documentação do escopo) e devolve ao coordenador |
| `duke-adversario` | tenta quebrar o que os outros produziram — Gate, Policy, autoridade, revogação, replay, corridas, auditoria |
| `duke-revisor` | confere a documentação contra o código, os testes e os resultados |

Quando o tipo de agente não estiver disponível na sessão, use um agente
de propósito geral com o conteúdo do arquivo do papel no pedido.

## 3. Notas práticas deste repositório

### 3.1 Idioma e forma

- Documentação, comentários, mensagens de commit e relatórios em
  português; as mensagens da suíte (`kernel/src/testes*`) em ASCII.
- `kernel` e `politica` não citam nomes do Internet Computer (icp,
  canister, candid, dfinity, web3, pocketic) — conferido por `cargo xtask
  invariantes`, que também confere a árvore de arquivos do README (todo
  `.rs` ou `.ld` novo entra na seção `## Arquitetura`) e a tabela de
  comandos.

### 3.2 Antes de cada push

Os passos do job `Formatação e lints` de `.github/workflows/ci.yml` nos
pacotes que mudaram: a formatação (o workspace, `iniciador`, `programas`,
`kernel` e `sdk/modelo`), os testes do hospedeiro, o clippy com
`-D warnings` (o kernel nas duas arquiteturas, com e sem `modo-teste`),
`cargo xtask invariantes` e o `cargo doc` com
`-D rustdoc::broken_intra_doc_links`. A suíte roda no QEMU por
`cargo xtask test --arch x86_64|aarch64`.

Nunca entram num commit: uma linha temporária de filtro da suíte, uma
mutação aplicada.

### 3.3 Os recursos do contêiner

- O espaço em disco da sessão é limitado, e os diretórios de build
  (`target/` e `kernel/target/`) passam de 10 GB. Uma worktree que
  compila o kernel e os programas precisa de vários GB: confira o espaço
  (`df`) antes de dar uma worktree com build a um agente; sem espaço, os
  agentes paralelos ficam com trabalho de leitura, análise e revisão, e as
  rodadas que compilam passam pelo coordenador, uma de cada vez.
- A suíte e as bancadas no QEMU usam muita CPU, e vários casos medem
  tempo: o coordenador agenda as rodadas pesadas para não disputarem a
  máquina.

### 3.4 As mutações

Uma de cada vez, sempre restauradas; o resultado que vale é o da última
rodada de cada uma. A mutação que sobrevive é investigada: um teste fraco
ganha reforço; um código equivalente é explicado e documentado.
