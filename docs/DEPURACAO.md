# Depuração

Este documento existe porque o ferramental de depuração de Rust é escrito para
programas que rodam **sobre** um sistema operacional, e aqui nós somos o
sistema operacional. Boa parte do que funciona lá não funciona aqui — e a
parte que funciona muitas vezes precisa de uma volta a mais.

## O que o Duke tem

Quatro ferramentas, cada uma respondendo a uma pergunta diferente.

| Pergunta | Ferramenta |
|---|---|
| O que aconteceu, e em que ordem? | `log.tail` pelo canal do agente |
| Qual é o estado do sistema agora? | `system.info`, `memory.*`, `tasks.*`, `irq.stats` |
| Onde exatamente o kernel morreu? | `traps.stats` + `cargo xtask simbolo` |
| O que o processador está fazendo neste instante? | `cargo xtask debug` (GDB/LLDB) |

As três primeiras vêm de dentro: o kernel se descreve. A quarta vem de fora,
pelo emulador, e é a única que funciona quando o kernel ainda não subiu ou
quando morreu de um jeito que ele próprio não consegue relatar.

---

## Depurador: `cargo xtask debug`

```bash
cargo xtask debug                 # x86_64, com gdb
cargo xtask debug --arch aarch64  # aarch64, com lldb
```

O comando compila, sobe o QEMU **congelado antes da primeira instrução** e
imprime a linha exata para conectar. O emulador implementa o protocolo de
depuração remota do GDB, e é isso que dá breakpoint, execução passo a passo,
pilha de chamadas, variáveis locais e registradores num kernel bare-metal.

O que se consegue com isso, na prática:

```
(lldb) breakpoint set --name lancar
(lldb) continue
(lldb) bt
* frame #0: <Executor>::lancar(self=…, tarefa=…) at executor.rs:85:25
  frame #1: duke::inicio_comum(canal_agente=true) at main.rs:160:18
  frame #2: inicio_aarch64(dtb=1140850688) at mod.rs:169:5
  frame #3: _start + 140
(lldb) frame variable
(duke::tarefas::Tarefa) tarefa = {
  id = (__0 = 1)
  nome = (data_ptr = "agent…", length = 5)
  futuro = { pointer = { pointer = 0x1000000830, vtable = 0x400b0f68 } }
}
```

A pilha vai até `_start`, o argumento do device tree aparece decodificado, e o
`Pin<Box<dyn Future>>` mostra o par ponteiro/vtable. É exatamente o tipo de
inspeção de layout que os manuais de depuração descrevem para `Vec` e `Box`,
funcionando em bare-metal.

### Por que `gdb` no x86 e `lldb` no ARM

O `gdb` das distribuições é compilado para um alvo só — o do host. Depurar
aarch64 com ele exigiria o pacote `gdb-multiarch`. O `lldb` é construído sobre
o LLVM e carrega todos os alvos no mesmo binário, então funciona para a
arquitetura cruzada sem instalar nada.

### Por que a base do kernel no x86 é fixa

O binário do kernel é um executável independente de posição, ligado a partir
do zero, e o bootloader o carrega em outro lugar. Se esse lugar for escolhido
em tempo de execução, todo endereço que o kernel reporta está deslocado por
uma constante que só se descobre perguntando a ele — e um depurador conectado
*antes* do boot não tem a quem perguntar.

Por isso `arch::x86_64::BASE_DO_KERNEL` fixa a imagem em
`0xFFFF_8000_0000_0000`, o primeiro endereço canônico da metade alta. É a
convenção de quase todo kernel de 64 bits, e não é só estética: na fase 1, com
processos, a metade baixa inteira fica para o userspace.

No ARM não há bootloader e o script do linker já fixa os endereços finais, então
o deslocamento é zero.

---

## Símbolos: `cargo xtask simbolo`

Fecha o ciclo com o canal do agente. O kernel reporta endereços crus — é a
decisão certa, porque ele não carrega a própria tabela de símbolos — e este
comando os cruza com o DWARF do binário.

```bash
$ cargo xtask agent debug.trigger '{"kind":"fatal"}'
{"result":{"scheduled":"fatal","survived":false,…}}

$ cargo xtask agent traps.stats
{"result":{"last":{"name":"page_fault","pc":18446603336221253026,…}}}

$ cargo xtask simbolo 18446603336221253026
0xffff80000000dda2
  core::ptr::write_volatile::<u64>
      …/core/src/ptr/mod.rs:2269:9
  inlinado em duke::arch::x86_64::disparar_falha_fatal
      kernel/src/arch/x86_64/mod.rs:337:14
```

A cadeia de inlining não é enfeite. Num kernel quase tudo é inlinado, e o
quadro mais interno costuma ser uma função da `core` que não diz nada: `pc`
caindo em `ptr::write_volatile` só vira informação quando se vê quem a chamou.

Aceita decimal (que é o que sai do JSON) e hexadecimal (que é o que sai de um
depurador).

---

## Desmontagem: `cargo xtask asm`

```bash
cargo xtask asm --release consumir_pilha
```

Mostra o que o otimizador realmente produziu, com as linhas de Rust
intercaladas.

Este comando nasceu de um bug real. O teste de estouro de pilha passava em
debug e pendurava em release: a recursão era `consumir_pilha(n + 1) + n`, e o
LLVM reconhece esse formato — recursão cujo retorno entra numa operação
associativa — e o converte num laço com acumulador. Um laço não consome pilha,
então o estouro nunca acontecia e o teste esperava para sempre.

A evidência estava a um comando de distância: a versão release da função não
tinha instrução de chamada nenhuma. Depois da correção:

```
00000000000073f0 <duke::testes::consumir_pilha>:
; fn consumir_pilha(profundidade: u64) -> u64 {
    73f0:  subq  $0x18, %rsp          <- quadro de pilha de verdade
;         let eco = consumir_pilha(core::ptr::read_volatile(&bloco[0]) + 1);
    7401:  callq 0x73f0 <…consumir_pilha>   <- chamada recursiva de verdade
```

Detalhe que só a desmontagem revela: o quadro tem 0x18 bytes, não os 128 do
array declarado. O LLVM reduziu o array às duas posições efetivamente escritas.
O que faz o teste funcionar não é o tamanho do bloco — é a escrita volátil
*depois* da chamada, que obriga o quadro a sobreviver a ela.

---

## O que não funciona aqui, e por quê

Vale ser explícito, porque todas estas ferramentas são excelentes no lugar
delas e a tentação de tentar usá-las é real.

| Ferramenta | Situação |
|---|---|
| `lldb`/`gdb` direto no binário | **Não.** Não há processo para anexar. O caminho é o gdbstub do QEMU, que é o que `cargo xtask debug` faz. |
| **Miri** | **Não.** Interpreta o modelo de execução de Rust, e este kernel é quase todo assembly embutido, MMIO e registradores de sistema — coisas que Miri, por construção, não modela. |
| **ASan / TSan / LSan** | **Não.** Sanitizers são bibliotecas de runtime: dependem de `malloc` interceptável, de threads e de um SO. Nós somos o SO. |
| **Tokio / `tracing`** | **Não.** Exigem `std`. O executor em `tarefas/` cumpre o papel do runtime, e `crate::log` o de observabilidade estruturada. |
| `cargo flamegraph` / `perf` | **Não.** Dependem de contadores de performance expostos pelo SO hospedeiro ao processo. |
| **Criterion** | **Não** como está: depende de `std`. Medir dentro do kernel é possível com o timer, e é assunto de uma fase futura. |
| `cargo rustc -- --emit=asm` | **Sim**, e é útil. `cargo xtask asm` faz o equivalente sobre o binário já ligado, que é o que de fato executa. |
| **DWARF e símbolos** | **Sim.** É o que `cargo xtask simbolo` e o depurador consomem. |
| **Valgrind** | **Não.** Emula um processo de userspace. |

### A substituição honesta para o que falta

O que ASan e TSan fariam, este kernel precisa fazer por construção:

- **Estouro de pilha** → guard page nas duas arquiteturas, com teste
  automatizado que provoca o estouro de verdade.
- **Corrupção de heap** → o alocador mantém invariantes verificáveis, e
  `heap.stats` as expõe (blocos livres, maior bloco, contagem de falhas).
- **Escrita fora do mapeado** → a MMU. É o ASan do kernel, em hardware.
- **Data race** → não há segundo núcleo ainda. Quando houver, a disciplina de
  `sem_interrupcoes` deixa de bastar e as filas de `tarefas/` terão de virar
  atômicas de verdade. Está anotado onde importa.

---

## O ciclo

Os dois guias que originaram este documento convergem no mesmo ponto, e ele
vale mais que qualquer comando:

```
observação → hipótese → instrumentação → experimento → evidência
           → correção → teste de regressão
```

O que muda num kernel é só o passo da instrumentação, porque as ferramentas
são outras. O resto é idêntico — e a parte que este projeto leva a sério é a
última: **todo bug encontrado vira caso na suíte**. Foi assim com o byte
espúrio no enquadramento do canal, com o endereço não canônico em
`paging.translate`, com o vazamento de tabelas intermediárias e com o estouro
de pilha que o otimizador apagava.

### Quando o comportamento está certo e o defeito não

Nem todo defeito tem sintoma observável, e os que não têm são os que a suíte
não pega — porque uma suíte pergunta pelo resultado.

O driver de rede entregava o mesmo buffer ao dispositivo mais de uma vez, o
que perde um pacote e duplica outro. O ARP continuava indo e voltando, os
contadores continuavam batendo, e as noventa e cinco perguntas da suíte
continuavam respondidas — todas sobre o resultado, nenhuma sobre o meio.

O que expôs o defeito foi uma sonda sobre um invariante interno: quantos
descritores estão em uso. Quatro buffers deveriam gastar quatro; gastavam
oito. A contagem não é o comportamento, é a estrutura por baixo dele, e é aí
que um defeito assim aparece primeiro.

A regra que ficou: **quando o comportamento observável está certo e a
desconfiança persiste, instrumente a invariante, não a saída** — e, quando a
invariante se confirma errada, é ela que vira o caso na suíte.

### Medir a suíte pela mutação

Uma suíte verde diz que os casos passam, não que eles testam. A forma de
descobrir a diferença é quebrar a garantia de propósito e ver quem reclama —
e vale fazer isso com as garantias centrais, não só com a correção da vez.

Feito aqui, com quatro delas: quebrar o `W^X` da carga de programas, desligar
a conferência de limites das chamadas de sistema, entregar o mesmo frame duas
vezes e vazar o frame ao desmapear. As quatro foram pegas, três por um caso
com nome — a do alocador mata o kernel antes da suíte rodar, e o que se vê é
o modo post-mortem respondendo.

A quinta não foi. Removendo as três barreiras de memória de
`virtio::fila`, os casos todos passam. A reordenação contra a qual
elas defendem não acontece num emulador coerente de um núcleo só, e nenhum
caso possível a produziria. A resposta não foi inventar um teste: foi
escrever a lacuna no comentário da própria linha, onde quem for apagá-la vai
ler.

O mesmo vale para a ordem de publicação do registro de interrupção de
`virtio`: invertendo os dois passos de volta, a suíte passa inteira, porque a
janela dura duas instruções e nenhum caso consegue cair dentro dela. As duas
lacunas estão escritas no comentário da linha que as contém — é a única
defesa que sobra quando a suíte não é uma, e vale escrevê-la **na correção**,
enquanto a medição ainda está fresca.

E uma armadilha de método, porque ela quase produziu um achado falso: a
mutação precisa ser **confirmada aplicada** antes de a ausência de falhas
significar algo. Um `grep -c` que devolveu zero interrompeu um encadeamento
`&&`, a mutação nunca chegou ao arquivo, e a suíte passou por não haver nada
para pegar. Uma conclusão negativa a partir de um experimento que não rodou é
pior que nenhuma conclusão.

### Injetar pela fronteira, e não pelo código

As mutações acima quebram o kernel por dentro. Há uma segunda família, mais
fiel, para tudo que o kernel **recebe de fora**: deixar o código intacto e
corromper a entrada.

Os dois canais por onde entra dado alheio aceitam isso sem recompilar nada:

- **O canal do agente.** Um `socket.connect` no `target/agent-<arch>.sock` e
  qualquer byte que se queira. Foi assim que apareceu o `id` que saía cru
  dentro da resposta: nove pedidos malformados, e as respostas conferidas com
  `json.loads` — o que separa "o kernel respondeu" de "o kernel respondeu
  algo legível".

- **O device tree, no ARM.** `qemu-system-aarch64 -machine virt,dumpdtb=x.dtb`
  entrega o blob que a máquina usaria; envenenar um campo de trinta e dois
  bits e devolvê-lo com `-dtb x.dtb` exercita o leitor com exatamente o que
  ele veria de um firmware corrompido. Um `nameoff` alterado bastou para o
  kernel pendurar no boot sem emitir um byte.

A vantagem sobre a mutação de código é que o experimento continua válido
depois da correção: o mesmo blob, o mesmo pedido, e o que muda é a resposta.

### O arnês também é código

Ver `cargo xtask test` dizer "todos os testes passaram" não é evidência de que
algo rodou. Antes de confiar numa rodada verde, vale conferir que o arnês
distingue as duas coisas — encerrando o kernel com sucesso **antes** da suíte,
ou desligando a máquina por um caminho que não seja o canal de resultado
(`hvc #0` com `SYSTEM_OFF` no ARM, a porta ACPI `0x604` no x86). Foi assim que
apareceu o sucesso do ARM valendo `0`, o mesmo código de qualquer saída limpa
do QEMU.

### Quando a lente não acha nada

Acontece, e o resultado é legítimo — desde que a varredura fique registrada,
ou a rodada seguinte a refaz do zero. Duas que voltaram limpas:

- **Ordenação de memória.** Cruzar, por variável atômica, as escritas `Release`
  com as leituras que as consomem: um `Release` lido com `Relaxed` não é par
  nenhum, e falha só no ARM — metade da CI passa por construção. Atenção ao
  falso positivo: em `virtio::registrar`, `isr` e `nome` são escritos
  `Relaxed` de propósito e publicados pelo `Release` de `linha`. O par existe,
  só não está na mesma variável.

- **Disciplina de travas.** Varrer todo `.lock()` que não tenha
  `sem_interrupcoes` acima. As sete ocorrências são legítimas: inicialização
  antes de a interrupção existir, contrato `unsafe` documentado, ou dentro de
  handler com as interrupções já mascaradas pela entrada de exceção.
