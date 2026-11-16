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
soluções; conflitos de integração; validação de segurança; CI; o
compilador da validação (ver 4.1); commit final; decisões utilizadas;
novas decisões, se houver; decisões que continuam CLOSED; próximos
trabalhos.

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

## 4. O compilador

A política híbrida, adotada pelo dono do projeto em 16 de novembro de
2026 e permanente como o resto deste arquivo: um compilador fixado para
todo trabalho oficial, e um canário que acompanha o nightly à parte, sem
bloquear nada.

### 4.1 O compilador oficial

- O canal oficial é o do `rust-toolchain.toml` da raiz — hoje
  **`nightly-2026-11-15`**: `rustc 1.102.0-nightly (5f4effd57 2026-11-13)`
  e `cargo 1.102.0-nightly (ede6cefea 2026-11-11)`. O
  `sdk/modelo/rust-toolchain.toml` tem o mesmo canal.
- Toda sessão, worktree, agente e job da CI usa esse compilador. O rustup
  o instala sozinho, pelo arquivo, na primeira chamada do cargo; as
  worktrees e os agentes paralelos o compartilham — o toolchain mora em
  `~/.rustup`, um só por máquina. Nenhum agente instala, fixa ou sobrepõe
  outro — menos a sessão que prepara uma promoção, para as medidas de 4.3,
  e só em execuções não oficiais; o candidato sai da máquina depois.
- **Nenhuma validação oficial usa outro compilador em silêncio.** Não se
  usa `cargo +<toolchain>`, `RUSTUP_TOOLCHAIN`, `rustup override` ou
  `rustup default` no projeto, nem `RUSTC`, `RUSTC_WRAPPER` e afins, nem
  as chaves `build.rustc*` do config do cargo.
- O `cargo xtask` confere o compilador no começo de todo comando — menos o
  `compilador`, que o relata e sai com falha fora do oficial, e a ajuda — e
  recusa rodar com um desvio. São desvios:
  - o `rust-toolchain.toml` da árvore diferente do do commit: uma promoção
    em preparo é uma execução não oficial até o commit;
  - o toolchain ativo que não é o canal com o host, na raiz ou num
    diretório de build — um `rustup override` só ali;
  - o cargo, ou o rustc que compilou o próprio `xtask`, de outro
    toolchain;
  - as variáveis `RUSTC`, `RUSTC_WRAPPER` e `RUSTC_WORKSPACE_WRAPPER`, e as
    chaves `build.rustc*` do config do cargo — lido pelo próprio cargo, em
    cada diretório de build.
- `DUKE_OUTRO_COMPILADOR=1` declara a execução **não oficial**, mesmo com o
  compilador oficial: ela roda com um aviso, a proveniência registra
  `"oficial": false`, e o resultado dela não vale como validação. A CI
  oficial nunca usa essa variável.
- O `cargo xtask invariantes` confere:
  - que o canal tem data e é o mesmo nos dois arquivos, e que o
    `CLAUDE.md` o cita;
  - que não há outro `rust-toolchain` no repositório;
  - que o config do cargo dos diretórios com `.cargo/` não troca o
    compilador;
  - que o `xtask` não chama o cargo nem o rustc com outro toolchain;
  - que os workflows oficiais só usam as ações permitidas — o checkout, o
    cache, a publicação de artefatos e a conferência do compilador —, não
    sobrepõem o compilador e o conferem (`.github/actions/compilador`)
    depois de cada checkout, antes do cache e de qualquer `cargo`, com o
    canal em toda chave de cache;
  - que o canário não roda nos pushes, não usa o cache da CI nem publica a
    proveniência, e repete os comandos do job de lints — cada um no
    diretório dele, e os laços das arquiteturas —: quando a CI muda, ele
    muda junto.
- `cargo xtask compilador` mostra o canal, o toolchain ativo, o
  `rustc -Vv`, o `cargo -V`, o compilador do próprio `xtask` e os desvios.
- **Todo relatório de validação registra o compilador**: o canal e o
  `rustc -V` — de `cargo xtask compilador` ou do log da CI.
- Depois de uma promoção, o toolchain antigo sai da máquina
  (`rustup toolchain uninstall <canal antigo>`). Cada um ocupa uns 1,3 GB,
  e o disco da sessão é curto (ver 3.3).

### 4.2 A CI oficial e o canário

- **A CI oficial** (`.github/workflows/ci.yml`) roda só com o compilador
  oficial. Cada job confere, logo depois do checkout, que o
  `rust-toolchain.toml` é o do commit, que nenhuma variável troca o
  compilador e que o `rustc` e o `cargo` são os do canal, e imprime a
  versão completa no log. O canal entra na chave de todo cache: um cache é
  do compilador que o encheu, e uma promoção começa caches novos, sem
  restaurar os do anterior.
- **O canário** (`.github/workflows/canario.yml`) é independente, semanal
  e não bloqueante.
  - Instala o nightly mais recente que tem todos os componentes, ou o canal
    pedido no disparo manual.
  - Roda o que o job de lints roda, nas duas arquiteturas: a formatação, o
    Clippy do hospedeiro, do kernel, do iniciador e dos programas, as
    invariantes, os testes do hospedeiro e a documentação.
  - Roda o SDK de fora do repositório, como o job `sdk-fora`.
  - Compila os kernels nas configurações da CI — no x86, sem SIMD —, o
    iniciador e os programas, e confere os tamanhos contra os tetos do
    `xtask`.
  - O relatório traz a versão completa do compilador e os tamanhos.
  - Não muda o toolchain oficial nem arquivo nenhum do projeto, não usa o
    cache da CI e não produz artefato oficial.
  - Não cobre a suíte no emulador, as bancadas nem o `cargo xtask elf`,
    que pedem o disco de testes: isso fica para a CI completa do commit da
    promoção.
  - Uma falha dele é um relatório com a causa provável e as primeiras
    linhas de erro, não um bloqueio. O resultado dele é informação para a
    próxima promoção.
- O GitHub só agenda um workflow que está no ramo padrão do repositório.
  Enquanto o ramo padrão não tiver o `canario.yml`, o agendamento não
  dispara, e o canário roda pelo disparo manual (`workflow_dispatch`) —
  no mínimo, pela sessão que prepara uma promoção.

### 4.3 A promoção

- **Ordinária**, a cada 4 semanas. **Extraordinária** quando:
  - o compilador novo traz uma correção de segurança relevante;
  - uma dependência ou o próprio Rust exige;
  - o kernel precisa de algo dele.
- **O candidato passa no canário.**
- **Antes de promover, mede-se o candidato contra o oficial:**
  - o uso de pilha da rodada da hora, nas duas arquiteturas;
  - o tamanho do kernel;
  - o tamanho dos programas — o `gestor` está perto do teto;
  - a duração da suíte;
  - o desempenho que importar.

  Os tamanhos saem do relatório do canário. A pilha, a duração e o
  desempenho saem de rodadas não oficiais da suíte com o candidato, na
  sessão que prepara a promoção (`DUKE_OUTRO_COMPILADOR=1`). Os números do
  oficial saem da proveniência e dos logs da CI. Uma regressão é
  investigada antes da promoção: a causa entendida, e corrigida ou aceita
  por escrito.
- **A promoção é um commit próprio, revisável.** Ele troca os dois
  `rust-toolchain.toml` juntos e a versão escrita em 4.1. Os ajustes que
  o compilador novo pedir — os lints do Clippy, a formatação — vão,
  quando possível, em commits separados, antes dela.
- **A CI completa passa verde no commit da promoção**, e confirma as
  medidas.
- Trocar o compilador é engenharia [B] dentro desta política. Uma mudança
  de arquitetura ou de segurança que o compilador novo force é [C].

### 4.4 A proveniência

- Todo artefato que o `xtask` compila deixa um registro em
  `target/proveniencia/`, um JSON por artefato. Vale para o kernel, o
  iniciador, cada programa e o modelo do SDK. O registro guarda:
  - o artefato: o tipo, o nome, o caminho, o SHA-256 e o tamanho;
  - a compilação: o alvo, a arquitetura, o perfil e as features;
  - o compilador: o `rustc -Vv` completo, o `cargo -V`, o toolchain ativo,
    o canal oficial, se a execução foi oficial, os desvios e se ela se
    declarou não oficial;
  - a fonte: o commit, se a árvore estava limpa, o `Cargo.lock` e o
    SHA-256 dele;
  - a execução da CI — o repositório, o workflow, o evento, o ref, o
    commit, o run (o id e o número), a tentativa, o job, o endereço e o
    runner —, ou nenhuma, fora dela;
  - a versão do formato e a hora do registro.
- O kernel e o iniciador dizem no log de quem compila onde ficou o
  registro, se o compilador foi o oficial e em que execução da CI.
- Cada job da CI que compila — todos menos o de lints — e a fumaça da rede
  principal publicam os registros como artefato (`proveniencia-*`), pelo
  mesmo mecanismo dos incidentes, guardados por 90 dias. O incidente de
  uma máquina parada guarda o registro do kernel que capturou, quando o
  acha.
- **Proveniência não é reprodução byte a byte.** O registro diz com que
  compilador, de que fonte e em que execução o artefato saiu. Compilar de
  novo, noutra máquina, não dá garantidamente os mesmos bytes: os caminhos
  absolutos do checkout e do registro do cargo entram nas localizações de
  pânico do `.rodata` e nas informações de depuração.
- É um registro de build, fora do Duke: não é autoridade, nem
  persistência, nem auditoria do sistema.
