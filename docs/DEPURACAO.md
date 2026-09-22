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
