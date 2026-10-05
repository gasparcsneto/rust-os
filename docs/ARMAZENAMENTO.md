# Armazenamento nativo — desenho da fase 8

## O que é

Os programas, os agentes e as pessoas do Duke guardam dados no **armazém**:
uma árvore de arquivos de texto montada em `/armazem`, gravável, com versão
por objeto, arrendamento para quem edita, e cada gravação confirmada só
depois de persistida. Não há um segundo sistema de autorização para ele, nem
uma segunda API: as operações são comandos do registro, chegam pelo mesmo
`pedir` (ou pelo canal, ou pelo interpretador), passam pelo mesmo gate e vão
para a mesma cadeia de auditoria.

## Seis conceitos, e onde cada um mora

Eles não se misturam. Cada um tem um lugar, uma pergunta e uma recusa.

| Conceito | A pergunta | Onde mora | A recusa |
|---|---|---|---|
| **Autorização** | esta identidade pode escrever (ou ler)? | `autorizacao::autorizar` — a permissão `fs.write` (ou `fs.read`) no papel, ∩ manifesto do programa | `DENY_PERMISSION`, `DENY_ROLE`… |
| **Alcance de caminho** | este caminho está dentro da autoridade efetiva? | a mesma decisão: o recurso da permissão na política (`recurso <papel> fs.write <prefixo>…`), sobre o caminho na forma normal | `DENY_RESOURCE` |
| **Arrendamento** | alguém tem agora o direito exclusivo de editar este objeto? | a tabela de `coordenacao` (a mesma da interface), com o recurso `fs:<caminho>` — só o arrendamento dela; a versão dela não é usada | `CONFLICT`, com `"conflict":"lease"` |
| **Versão** | a mutação é contra o estado que quem pede leu? | o armazém (`armazem::Armazem`): cada objeto tem a versão da última mudança | `CONFLICT`, com `"conflict":"version"` e a versão de agora |
| **Persistência** | a mudança está no disco? | `persistencia::gravar_armazem`: um registro do journal, escrito, descarregado e ancorado no TPM | `ERROR`, e nada muda |
| **Auditoria** | quem decidiu o quê, e o que aconteceu? | a decisão do gate; e o que o comando fez, em nome do mesmo principal e com o número da decisão, **no mesmo registro** do journal que a mudança — a decisão vem antes na cadeia, então está nele ou num anterior, nunca depois | — |

A ordem de uma mutação é sempre esta, e cada passo só usa o seu conceito:

1. o gate decide (autorização ∩ manifesto, e o alcance do caminho), e grava a
   decisão na auditoria — com o número dela na cadeia, que o handler recebe
   junto com a autoridade;
2. com a ordem das gravações na mão (`persistencia::em_ordem`):
   1. a persistência está disponível? — senão, `ERROR`, nada muda;
   2. o arrendamento do objeto, se há, é de quem pede? — senão, `CONFLICT`
      (lease);
   3. a versão esperada é a de agora? — senão, `CONFLICT` (version);
   4. o armazém prepara a mudança, sem aplicá-la (tetos, caminho, tipo);
   5. a auditoria registra o que o comando vai fazer (`mudanca a gravar:
      versao N; decisao D`), em nome de quem o gate autorizou; e a mudança
      vai para o journal num registro que **exige** esse registro da
      auditoria — e, como a cadeia é gravada em ordem, a decisão D vai
      nele ou num anterior. Se a gravação falha, nada muda em memória;
   6. só então a mudança vale em memória;
3. cada recusa depois do gate (persistência, arrendamento, versão, lugar,
   teto) vai para a auditoria como o resultado do comando autorizado, com
   o número da decisão.

Por que um registro da execução, e não só a decisão: a decisão é gravada
pelo gate **antes** de o handler ter a ordem das gravações na mão, e o
coletor da auditoria pode levá-la ao disco sozinha nesse meio tempo. O
registro da execução é feito com a ordem na mão, e é ele que o registro da
mudança exige — a mesma solução das operações administrativas (`executada`
na mesma ordem que `concluir`).

## Versão

Cada mutação recebe a versão seguinte de um contador **do armazém inteiro**,
que só cresce e é persistido. A versão de um objeto é a da última mudança
nele; um objeto que não existe tem versão 0. Assim um objeto apagado e
criado de novo não volta a uma versão que alguém já leu: quem guardou a
versão 3 do antigo não escreve no novo achando que é o mesmo.

- `fs.write` com `expect_version: 0` cria — e recusa se já existe;
- com `expect_version: N` substitui — e recusa se a versão não é `N`;
- `fs.append` e `fs.delete` exigem a versão de agora.

## Arrendamento

Opcional, e exclusivo quando tomado: `fs.claim` toma o objeto por um prazo
(1 s a 5 min, renovado pela atividade do titular), `fs.release` o solta. O
caminho pode ainda não ter arquivo — quem vai criá-lo o arrenda antes —,
mas não pode ser um diretório. A conferência do arrendamento numa mudança
é só do arrendamento: a versão da tabela de coordenação não é usada nem
mexida (`Tabela::conferir`).
Enquanto vale, só o titular muda o objeto — a versão continua sendo exigida
dele também. Sem preempção: ninguém toma o arrendamento de outro por ter um
papel maior, nem o sistema. Ele acaba pelo titular, pelo prazo, pelo fim da
sessão ou da identidade do titular, ou por `lease.revoke` com a prova de um
administrador (com `path`). O titular é o de sempre: a sessão e a
identidade — um processo arrenda em nome de quem o lançou. A autoridade
local (`sistema`, os processos do sistema) não tem titular, como na
interface: não arrenda, e só muda um objeto livre — o arrendamento de uma
pessoa vale contra ela como contra qualquer um.

## Persistência

O armazém mora no journal da partição de estado, num tipo de registro
próprio (`ARMAZEM`), que avança a âncora do TPM e não sobe a geração
administrativa — um arquivo não é autoridade. As entradas são
`ARQUIVO_GRAVADO [caminho, versão, conteúdo]` (o conteúdo inteiro: o
journal guarda resultados, e não pedidos), `ARQUIVO_APAGADO [caminho,
versão]` e, na base de uma compactação, `ARMAZEM_PROXIMO [versão]`. O
journal cifra e autentica cada registro, e o encadeia ao anterior: o
conteúdo dos arquivos está cifrado no disco, e um disco anterior ao que o
TPM viu é recusado no boot como sempre foi.

**Estrita.** Uma mudança no armazém nunca vale só em memória: sem a
persistência disponível, a operação é recusada antes de mudar qualquer
coisa; com a gravação falhando no meio, nada muda (e a persistência fica
indisponível, como em qualquer outra falha de gravação).

**Tetos.** O armazém divide a partição com o estado de autoridade, e não
pode tomar o lugar dele: uma revogação que não cabe no journal por causa de
arquivos seria um ataque de disponibilidade a uma operação de segurança.
Então: 16 KiB por arquivo, 256 arquivos, 512 KiB no armazém inteiro — a
base de uma compactação com o armazém cheio fica bem abaixo do ponto em que
a região compacta. O teto total é metade do que o primeiro desenho dizia
(1 MiB): o armazém mora também no heap do kernel, que tem 4 MiB e é de
todos, e um armazém cheio não pode deixar sem memória uma operação de
segurança. A compactação copia um arquivo de cada vez, e não o armazém
inteiro.

## Caminhos

Na forma normal da política (`politica::caminho`), abaixo de `/armazem`.
Cada componente tem de 1 a 64 bytes de `[A-Za-z0-9._-]` e não é `.` nem
`..`; até 8 níveis abaixo de `/armazem`. Diretórios são implícitos: existem
enquanto há arquivo abaixo deles. Um arquivo não pode ter o nome de um
diretório que existe, nem ficar abaixo de um arquivo.

## Leitura

Pelo VFS: o armazém é mais um sistema de arquivos montado, e `fs.read`,
`fs.list` e o `abrir` dos processos o alcançam pelo mesmo gate de sempre
(`fs.read` com o alcance de caminho). `fs.stat` diz a versão, o tamanho e o
arrendamento de um caminho, sob `fs.read`.

O nó de um arquivo, para o VFS, é a **versão** dele: única no armazém e
nome de exatamente um conteúdo. Um descritor aberto antes de uma mudança
não lê o conteúdo novo pelo nó velho, nem metade de cada um: recebe
`Erro::Mudou` (no processo, `MUDOU`, -17), e abrir de novo dá o de agora.
Os diretórios têm um número próprio, estável enquanto existem.

## A política padrão

A capacidade nova é concedida **explicitamente**, por linhas da política —
nunca por código:

```text
papel sistema … fs.write …
recurso sistema fs.write /armazem
papel operador … fs.write …
recurso operador fs.read … /armazem/compartilhado
recurso operador fs.write /armazem/compartilhado
papel administrador … fs.write …
recurso administrador fs.read … /armazem/compartilhado
recurso administrador fs.write /armazem/compartilhado
```

O `fs.read` do sistema já alcançava `/`. O observador não escreve nem lê.
Um programa só escreve se o manifesto dele declara `fs.write`.

Duas consequências de regras que já existiam, e que o desenho seguiu em vez
de abrir exceção:

- **O administrador.** O papel dele é o teto do que um administrador
  delega (`Politica::cabe_em`): o operador tem de caber nele para ser
  atribuível. Então o teto ganha exatamente o alcance do operador. As
  permissões comuns de um administrador não se exercem — uma chave de
  administrador não abre sessão de agente —: é teto, e não uso.
- **A emergência.** O `sistema` da política de emergência é, por regra já
  consolidada, o **mesmo texto** do da padrão (sem política no disco, a
  autoridade máxima não encolhe nem vira curinga). A linha de `fs.write`
  do sistema vem junto, escrita, e não por código. Os outros papéis não
  existem na emergência, e nada mais muda.

## O que não está aqui

- Conteúdo binário: os dados vão em texto UTF-8, no JSON do pedido.
- Cotas por papel ou por titular: os tetos são do armazém inteiro.
- Diretórios explícitos, renomear, links.
- Gravações agrupadas: cada mutação é um registro, e cada registro um
  avanço do contador do TPM.
