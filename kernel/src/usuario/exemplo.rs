//! Programas de usuário de exemplo, em ELF64 montado à mão.
//!
//! # Por que o ELF é escrito em assembly, e não compilado à parte
//!
//! Compilar um programa separado exigiria um segundo alvo de build, um script
//! de linker próprio e a ordenação entre os dois builds. Nada disso é difícil,
//! mas é infraestrutura — e o que está em teste aqui é o **carregador**.
//!
//! Emitir o ELF no mesmo assembly do programa mantém o alvo único e dá uma
//! vantagem real: cada byte do cabeçalho é escolhido e conferível, então uma
//! falha do carregador não pode ser confundida com uma peculiaridade do
//! linker. O assembler calcula os deslocamentos e tamanhos sozinho, de modo
//! que editar o programa não desalinha o cabeçalho.
//!
//! **A fraqueza do arranjo, dita em voz alta:** quem escreve o cabeçalho e
//! quem o lê são a mesma pessoa, então um mal-entendido sobre o formato
//! apareceria dos dois lados e se cancelaria. Por isso a imagem é conferida
//! por ferramenta independente — `cargo xtask elf` roda o `llvm-readelf` sobre
//! os bytes embutidos. Um programa compilado à parte continua sendo o passo
//! natural seguinte.
//!
//! # O que estes programas exercitam
//!
//! O exemplo usa endereços **absolutos** para alcançar a mensagem, e não mais
//! deslocamentos relativos ao ponteiro de instrução. É de propósito: só
//! funciona se o carregador tiver honrado `e_entry` e o `p_vaddr` de cada
//! segmento. Ele também lê a `.bss` — os bytes que o segmento pede na memória
//! além do que traz do arquivo — e sai com um código diferente se encontrar
//! lixo ali.
//!
//! # O mapa que os dois segmentos desenham
//!
//! ```text
//!   BASE          ┌──────────────┐
//!                 │    código    │  R+X
//!   BASE + 4 KiB  ├──────────────┤
//!                 │    dados     │  R+W, com 8 bytes de .bss no fim
//!                 └──────────────┘
//! ```

/// Código de saída que o invasor usaria se a proteção falhasse.
///
/// Se este valor aparecer em `ultima_saida`, o processo conseguiu ler a
/// memória do kernel e seguiu em frente — que é exatamente o que ring 3
/// existe para impedir.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_INVASOR: i64 = 99;

/// Código de saída que o programa de exemplo devolve quando tudo deu certo.
///
/// Um valor arbitrário e improvável: se ele aparecer do outro lado, veio daqui
/// e de nenhum outro lugar.
pub const CODIGO_DE_SAIDA: i64 = 42;

/// Código de saída que o programa carregado por `executar` devolve.
///
/// Distinto do do pai de propósito: é o que prova que a troca de imagem
/// aconteceu de verdade, e que quem saiu com ele foi o filho.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_FILHO: i64 = 24;

/// Texto que o programa carregado por `executar` escreve.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const MENSAGEM_DO_FILHO: &str = "filho por exec";

/// Código de saída quando a `.bss` chegou com lixo, ou quando `executar`
/// voltou — as duas são falhas do kernel, não do programa.
///
/// Distinto do de sucesso de propósito. Sem ele, um carregador que esquecesse
/// de zerar a memória além do que o arquivo traz passaria despercebido: o
/// programa terminaria normalmente e ninguém saberia que uma variável global
/// começou com o que o dono anterior do frame deixou lá.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DE_BSS_SUJA: i64 = 7;

/// Código de saída do programa que abre, lê e fecha um arquivo.
///
/// Distinto de todos os outros: se ele aparecer, quem saiu foi o leitor, e
/// ele chegou ao fim — o que inclui a última conferência que ele faz, que é
/// ler de novo no descritor fechado e exigir que falhe.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_LEITOR: i64 = 33;

/// Código com que o leitor sai quando alguma das chamadas não fez o que devia.
///
/// Uma saída com este código é falha do **kernel**, não do programa: cada
/// ponto que salta para cá é uma conferência que o leitor fez sobre o que
/// `abrir`, `ler` ou `fechar` devolveram.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DE_FALHA_DO_LEITOR: i64 = 8;

/// Código com que sai o filho que o leitor bifurca.
///
/// Ele existe para uma coisa só: o filho lê pelo descritor que o **pai**
/// abriu. Se a tabela não fosse herdada, aquele número não existiria do lado
/// dele e ele sairia pela falha.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_FILHO_DO_LEITOR: i64 = 34;

/// O diretório que o leitor tenta abrir, e que tem de ser recusado.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DIRETORIO_DO_LEITOR: &str = "/dados";

/// O motivo que o assembly compara, escrito como número nos dois blocos.
const _: () = {
    assert!(DIRETORIO_DO_LEITOR.len() == 6);
    assert!(crate::usuario::erro::NAO_EH_ARQUIVO == -10);
};

/// O arquivo que o leitor abre.
///
/// Metade de um contrato cujo outro lado é o `.ascii` do assembly logo
/// abaixo, nos dois blocos. A asserção de tamanho que vem a seguir é o que
/// impede as duas metades de divergirem em silêncio: mudar o caminho aqui sem
/// mudar lá quebraria o build, em vez de fazer o programa abrir outra coisa.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const ARQUIVO_DO_LEITOR: &str = "/saudacao.txt";

/// O tamanho que o assembly escreve em `TAM_CAMINHO_LE`.
const _: () = assert!(ARQUIVO_DO_LEITOR.len() == 13);

/// Texto que o exemplo manda para o descritor de erro.
///
/// Está numa constante porque o teste procura exatamente este texto no log,
/// em nível `error`. É o que prova que o descritor **escolhe o destino**.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DIAGNOSTICO: &str = "diagnostico de userspace";

unsafe extern "C" {
    #[link_name = "programa_exemplo_inicio"]
    static INICIO: u8;
    #[link_name = "programa_exemplo_fim"]
    static FIM: u8;
    #[link_name = "programa_invasor_inicio"]
    static INVASOR_INICIO: u8;
    #[link_name = "programa_invasor_fim"]
    static INVASOR_FIM: u8;
    #[link_name = "programa_filho_inicio"]
    static FILHO_INICIO: u8;
    #[link_name = "programa_filho_fim"]
    static FILHO_FIM: u8;
    #[link_name = "programa_leitor_inicio"]
    static LEITOR_INICIO: u8;
    #[link_name = "programa_leitor_fim"]
    static LEITOR_FIM: u8;
}

/// A imagem ELF do programa bem-comportado.
pub fn bytes() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const INICIO, &raw const FIM) }
}

/// A imagem ELF de um programa que tenta ler a memória do kernel.
///
/// Existe para provar que a proteção é real. Um ring 3 que se entra mas não
/// protege nada é só uma troca de contexto cara — o que precisa ser
/// demonstrado é que o processo **não alcança** o que não é dele, e que a
/// tentativa mata o processo e não o sistema.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_invasores() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const INVASOR_INICIO, &raw const INVASOR_FIM) }
}

/// A imagem ELF do programa que o filho carrega com `executar`.
///
/// Existe para que `exec` tenha para onde ir. Faz uma coisa só — escreve uma
/// linha e sai com um código próprio —, porque o que está em teste é a troca
/// de imagem, e não o que o programa novo faz depois dela.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_do_filho() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const FILHO_INICIO, &raw const FILHO_FIM) }
}

/// A imagem ELF do programa que abre, lê e fecha um arquivo.
///
/// Existe porque a tabela de descritores só é real se alguém sem privilégio a
/// usar. Um `abrir` que só o kernel chama é uma função; um `abrir` que um
/// processo chama é uma chamada de sistema — e a diferença entre as duas é
/// tudo que esta etapa acrescenta.
///
/// Ele confere o que recebe, e sai com [`CODIGO_DE_FALHA_DO_LEITOR`] se
/// alguma resposta não fizer sentido. A última conferência é a que mais
/// importa: depois de `fechar`, ele **lê de novo no mesmo número** e exige
/// que a leitura falhe. Sem ela, um `fechar` que não fizesse nada passaria.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_do_leitor() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const LEITOR_INICIO, &raw const LEITOR_FIM) }
}

/// # Safety
/// Os dois símbolos precisam delimitar uma região contígua da seção, na ordem
/// em que o bloco de assembly os emite.
unsafe fn entre(inicio: *const u8, fim: *const u8) -> &'static [u8] {
    // SAFETY: delegada ao chamador; o linker preserva a ordem dos rótulos.
    unsafe {
        let tamanho = fim.offset_from(inicio) as usize;
        core::slice::from_raw_parts(inicio, tamanho)
    }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.section .rodata.programa_exemplo
.balign 8

// O mapa que os segmentos desenham, em enderecos absolutos. O programa os usa
// diretamente: so funciona se o carregador tiver honrado `p_vaddr`.
.set BASE_USUARIO,     0x100000000
.set VADDR_CODIGO,     BASE_USUARIO
.set VADDR_DADOS,      BASE_USUARIO + 0x1000

.set OFF_DIAG,         32
.set TAM_DIAG,         24
.set OFF_NOME,         56
.set TAM_NOME,         5
.set DADOS_NO_ARQUIVO, 64
.set DADOS_NA_MEMORIA, DADOS_NO_ARQUIVO + 8

.set VADDR_MENSAGEM,   VADDR_DADOS
.set VADDR_DIAG,       VADDR_DADOS + OFF_DIAG
.set VADDR_NOME,       VADDR_DADOS + OFF_NOME
.set VADDR_BSS,        VADDR_DADOS + DADOS_NO_ARQUIVO

// O filho guarda a mensagem no inicio do proprio segmento de codigo, que e
// legivel, e comeca a executar 32 bytes adiante. Evita um segundo segmento
// para um programa de tres instrucoes.
.set OFF_CODIGO_FILHO, 32
.set TAM_MSG_FILHO,    14
.set TAM_MENSAGEM, 13

.global programa_exemplo_inicio
programa_exemplo_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_ex:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_ex - .Lelf_ex // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_ex - .Lcodigo_ex  // p_filesz
    .quad   .Lfim_codigo_ex - .Lcodigo_ex  // p_memsz
    .quad   4096                                 // p_align

    // segmento de dados: leitura e escrita. `p_memsz` maior que `p_filesz`
    // pede 8 bytes a mais do que o arquivo traz — a `.bss`, que o carregador
    // tem de entregar zerada.
    .long   1                                  // PT_LOAD
    .long   6                                  // PF_R | PF_W
    .quad   .Ldados_ex - .Lelf_ex  // p_offset
    .quad   VADDR_DADOS                        // p_vaddr
    .quad   VADDR_DADOS                        // p_paddr
    .quad   DADOS_NO_ARQUIVO                   // p_filesz
    .quad   DADOS_NA_MEMORIA                   // p_memsz
    .quad   4096                               // p_align

.Lcodigo_ex:
    // escrever(SAIDA, mensagem, tamanho)
    //
    // O endereco da mensagem e absoluto, e nao relativo ao ponteiro de
    // instrucao como era antes do ELF. E de proposito: so acerta se o
    // carregador tiver posto o segmento de dados onde o cabecalho pediu.
    mov     edi, 1
    movabs  rsi, offset VADDR_MENSAGEM
    mov     edx, offset TAM_MENSAGEM
    mov     eax, 1
    syscall

    // A `.bss` precisa ter chegado zerada.
    movabs  rax, offset VADDR_BSS
    mov     rax, [rax]
    test    rax, rax
    jne     .Lfalhou_ex

    // escrever(ERRO, diagnostico, tamanho)
    mov     edi, 2
    movabs  rsi, offset VADDR_DIAG
    mov     edx, offset TAM_DIAG
    mov     eax, 1
    syscall

    // bifurcar(): a partir daqui existem dois processos executando esta
    // mesma instrucao seguinte, cada um no seu espaco de enderecos.
    mov     eax, 4
    syscall
    test    rax, rax
    jnz     .Lpai_ex

    // O filho troca de imagem. `executar` so retorna se falhar.
    movabs  rdi, offset VADDR_NOME
    mov     esi, offset TAM_NOME
    mov     eax, 5
    syscall
    jmp     .Lfalhou_ex

.Lpai_ex:
    // sair(42)
    mov     eax, 0
    mov     edi, 42
    syscall

.Lfalhou_ex:
    mov     eax, 0
    mov     edi, 7
    syscall
.Lprender_ex:
    jmp     .Lprender_ex
.Lfim_codigo_ex:

.Ldados_ex:
    .ascii  "ola do anel 3"
    .space  OFF_DIAG - 13
    .ascii  "diagnostico de userspace"
    .space  OFF_NOME - OFF_DIAG - TAM_DIAG
    .ascii  "filho"
    .space  DADOS_NO_ARQUIVO - OFF_NOME - TAM_NOME
.Lfim_dados_ex:

.global programa_exemplo_fim
programa_exemplo_fim:

// --- o programa que o filho carrega ---------------------------------------
.balign 8
.global programa_filho_inicio
programa_filho_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_fi:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_FILHO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_fi - .Lelf_fi // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_fi - .Lcodigo_fi  // p_filesz
    .quad   .Lfim_codigo_fi - .Lcodigo_fi  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_fi:
    .ascii  "filho por exec"
    .space  OFF_CODIGO_FILHO - TAM_MSG_FILHO
    // A execucao comeca aqui: `e_entry` aponta 32 bytes adiante do segmento.
    mov     edi, 1
    movabs  rsi, offset VADDR_CODIGO
    mov     edx, offset TAM_MSG_FILHO
    mov     eax, 1
    syscall

    mov     eax, 0
    mov     edi, 24
    syscall
.Lprender_fi:
    jmp     .Lprender_fi
.Lfim_codigo_fi:

.global programa_filho_fim
programa_filho_fim:

// O leitor: dois caminhos no comeco do segmento de dados e um buffer logo
// depois, inteiro na `.bss` -- o carregador tem de entrega-lo zerado.
.set TAM_CAMINHO_LE,      13
.set OFF_DIRETORIO_LE,    16
.set TAM_DIRETORIO_LE,    6
.set DADOS_LE_NO_ARQUIVO, 24
.set OFF_BUFFER_LE,       32
.set TAM_BUFFER_LE,       64
.set DADOS_LE_NA_MEMORIA, OFF_BUFFER_LE + TAM_BUFFER_LE
.set VADDR_CAMINHO_LE,    VADDR_DADOS
.set VADDR_DIRETORIO_LE,  VADDR_DADOS + OFF_DIRETORIO_LE
.set VADDR_BUFFER_LE,     VADDR_DADOS + OFF_BUFFER_LE

// --- o leitor: abre, bifurca, le dos dois lados, escreve e fecha -----------
.balign 8
.global programa_leitor_inicio
programa_leitor_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
.Lelf_le:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                  // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_le - .Lelf_le              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_le - .Lcodigo_le       // p_filesz
    .quad   .Lfim_codigo_le - .Lcodigo_le       // p_memsz
    .quad   4096                                // p_align

    // segmento de dados: os caminhos vem do arquivo, o buffer nao. `p_memsz`
    // maior que `p_filesz` e o que pede os 64 bytes de buffer zerados.
    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_le - .Lelf_le               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_LE_NO_ARQUIVO                 // p_filesz
    .quad   DADOS_LE_NA_MEMORIA                 // p_memsz
    .quad   4096                                // p_align

.Lcodigo_le:
    // abrir(caminho, tamanho) -> descritor, ou negativo
    movabs  rdi, offset VADDR_CAMINHO_LE
    mov     esi, offset TAM_CAMINHO_LE
    mov     eax, 6
    syscall
    test    rax, rax
    js      .Lfalhou_le
    // O descritor fica num registrador que a chamada de sistema preserva:
    // o ponto de entrada empilha e desempilha tudo menos o retorno.
    mov     r12, rax

    // bifurcar() com um arquivo ja aberto. O filho herda a tabela de
    // descritores -- e a leitura dele, logo abaixo, e o que prova isso: com
    // uma tabela nova o numero em r12 nao existiria do lado dele.
    mov     eax, 4
    syscall
    test    rax, rax
    jnz     .Lpai_le

    // ler(descritor herdado, buffer, tamanho)
    mov     rdi, r12
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     edx, offset TAM_BUFFER_LE
    mov     eax, 7
    syscall
    test    rax, rax
    jle     .Lfalhou_le

    // sair(34): so o filho sai com este codigo.
    mov     eax, 0
    mov     edi, 34
    syscall

.Lpai_le:
    // ler(descritor, buffer, tamanho) -> quantos vieram
    //
    // O pai le do comeco, mesmo que o filho ja tenha lido: cada um levou a
    // propria copia da posicao. E o comportamento documentado na tabela, e
    // nao o do Unix, que compartilha a posicao entre pai e filho.
    mov     rdi, r12
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     edx, offset TAM_BUFFER_LE
    mov     eax, 7
    syscall
    test    rax, rax
    jle     .Lfalhou_le
    mov     r13, rax

    // escrever(SAIDA, buffer, quantos) -- e assim o que veio do disco
    // aparece do outro lado, escrito por um processo sem privilegio.
    mov     edi, 1
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     rdx, r13
    mov     eax, 1
    syscall

    // Escrever num descritor de arquivo tem de ser recusado: este kernel nao
    // tem escrita em arquivo, e aceitar mandaria o conteudo para o log como
    // se fosse uma mensagem.
    mov     rdi, r12
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     edx, 8
    mov     eax, 1
    syscall
    test    rax, rax
    jns     .Lfalhou_le

    // E ler num descritor de saida tambem: devolver zero fingiria um arquivo
    // vazio, e quem lesse ate o fim entenderia "acabou" em vez de "este
    // descritor nao le".
    mov     edi, 1
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     edx, offset TAM_BUFFER_LE
    mov     eax, 7
    syscall
    test    rax, rax
    jns     .Lfalhou_le

    // Abrir um diretorio tem de ser recusado, e com o motivo certo: -10 e
    // "nao e arquivo", que e diferente de "nao encontrado". Um kernel que
    // devolvesse o segundo mandaria o programa procurar o erro no lugar
    // errado.
    movabs  rdi, offset VADDR_DIRETORIO_LE
    mov     esi, offset TAM_DIRETORIO_LE
    mov     eax, 6
    syscall
    cmp     rax, -10
    jne     .Lfalhou_le

    // fechar(descritor)
    mov     rdi, r12
    mov     eax, 8
    syscall
    test    rax, rax
    jnz     .Lfalhou_le

    // E ler de novo no mesmo numero. Tem de falhar: a vaga voltou para a
    // tabela. Sem esta conferencia, um `fechar` que nao fizesse nada passaria
    // -- e o programa nao teria como saber.
    mov     rdi, r12
    movabs  rsi, offset VADDR_BUFFER_LE
    mov     edx, offset TAM_BUFFER_LE
    mov     eax, 7
    syscall
    test    rax, rax
    jns     .Lfalhou_le

    // sair(33)
    mov     eax, 0
    mov     edi, 33
    syscall

.Lfalhou_le:
    mov     eax, 0
    mov     edi, 8
    syscall
.Lprender_le:
    jmp     .Lprender_le
.Lfim_codigo_le:

.Ldados_le:
    .ascii  "/saudacao.txt"
    .space  OFF_DIRETORIO_LE - TAM_CAMINHO_LE
    .ascii  "/dados"
    .space  DADOS_LE_NO_ARQUIVO - OFF_DIRETORIO_LE - TAM_DIRETORIO_LE
.Lfim_dados_le:

.global programa_leitor_fim
programa_leitor_fim:

// --- o invasor -------------------------------------------------------------
.balign 8
.global programa_invasor_inicio
programa_invasor_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_inv:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_inv - .Lelf_inv // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_inv - .Lcodigo_inv  // p_filesz
    .quad   .Lfim_codigo_inv - .Lcodigo_inv  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_inv:
    // Le o primeiro endereco do kernel, que vive na metade alta.
    movabs  rax, 0xffff800000000000
    mov     rax, [rax]

    // Inalcancavel: a leitura acima e uma falha de protecao. Se chegarmos
    // aqui, o processo saiu com um codigo que o teste reconhece como
    // "a protecao nao funcionou".
    mov     eax, 0
    mov     edi, 99
    syscall
.Lprender_inv:
    jmp     .Lprender_inv
.Lfim_codigo_inv:

.global programa_invasor_fim
programa_invasor_fim:
"#
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.section .rodata.programa_exemplo
.balign 8

// O mapa que os segmentos desenham, em enderecos absolutos. O programa os usa
// diretamente: so funciona se o carregador tiver honrado `p_vaddr`.
.set BASE_USUARIO,     0x100000000
.set VADDR_CODIGO,     BASE_USUARIO
.set VADDR_DADOS,      BASE_USUARIO + 0x1000

.set OFF_DIAG,         32
.set TAM_DIAG,         24
.set OFF_NOME,         56
.set TAM_NOME,         5
.set DADOS_NO_ARQUIVO, 64
.set DADOS_NA_MEMORIA, DADOS_NO_ARQUIVO + 8

.set VADDR_MENSAGEM,   VADDR_DADOS
.set VADDR_DIAG,       VADDR_DADOS + OFF_DIAG
.set VADDR_NOME,       VADDR_DADOS + OFF_NOME
.set VADDR_BSS,        VADDR_DADOS + DADOS_NO_ARQUIVO

// O filho guarda a mensagem no inicio do proprio segmento de codigo, que e
// legivel, e comeca a executar 32 bytes adiante. Evita um segundo segmento
// para um programa de tres instrucoes.
.set OFF_CODIGO_FILHO, 32
.set TAM_MSG_FILHO,    14
.set TAM_MENSAGEM, 10

.global programa_exemplo_inicio
programa_exemplo_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_ex:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_ex - .Lelf_ex // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_ex - .Lcodigo_ex  // p_filesz
    .quad   .Lfim_codigo_ex - .Lcodigo_ex  // p_memsz
    .quad   4096                                 // p_align

    // segmento de dados: leitura e escrita. `p_memsz` maior que `p_filesz`
    // pede 8 bytes a mais do que o arquivo traz — a `.bss`, que o carregador
    // tem de entregar zerada.
    .long   1                                  // PT_LOAD
    .long   6                                  // PF_R | PF_W
    .quad   .Ldados_ex - .Lelf_ex  // p_offset
    .quad   VADDR_DADOS                        // p_vaddr
    .quad   VADDR_DADOS                        // p_paddr
    .quad   DADOS_NO_ARQUIVO                   // p_filesz
    .quad   DADOS_NA_MEMORIA                   // p_memsz
    .quad   4096                               // p_align

.Lcodigo_ex:
    // escrever(SAIDA, mensagem, tamanho)
    //
    // O endereco vem montado em tres pedacos de 16 bits porque o AArch64 nao
    // tem imediato de 64 bits. E absoluto, e nao relativo ao PC como era antes
    // do ELF: so acerta se o carregador tiver honrado `p_vaddr`.
    mov     x0, #1
    movz    x1, #(VADDR_MENSAGEM & 0xFFFF)
    movk    x1, #((VADDR_MENSAGEM >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_MENSAGEM >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_MENSAGEM
    mov     x8, #1
    svc     #0

    // A `.bss` precisa ter chegado zerada.
    movz    x9, #(VADDR_BSS & 0xFFFF)
    movk    x9, #((VADDR_BSS >> 16) & 0xFFFF), lsl #16
    movk    x9, #((VADDR_BSS >> 32) & 0xFFFF), lsl #32
    ldr     x9, [x9]
    cbnz    x9, .Lfalhou_ex

    // escrever(ERRO, diagnostico, tamanho)
    mov     x0, #2
    movz    x1, #(VADDR_DIAG & 0xFFFF)
    movk    x1, #((VADDR_DIAG >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_DIAG >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_DIAG
    mov     x8, #1
    svc     #0

    // bifurcar(): a partir daqui existem dois processos executando esta
    // mesma instrucao seguinte, cada um no seu espaco de enderecos.
    mov     x8, #4
    svc     #0
    cbnz    x0, .Lpai_ex

    // O filho troca de imagem. `executar` so retorna se falhar.
    movz    x0, #(VADDR_NOME & 0xFFFF)
    movk    x0, #((VADDR_NOME >> 16) & 0xFFFF), lsl #16
    movk    x0, #((VADDR_NOME >> 32) & 0xFFFF), lsl #32
    mov     x1, #TAM_NOME
    mov     x8, #5
    svc     #0
    b       .Lfalhou_ex

.Lpai_ex:
    mov     x8, #0
    mov     x0, #42
    svc     #0

.Lfalhou_ex:
    mov     x8, #0
    mov     x0, #7
    svc     #0
.Lprender_ex:
    b       .Lprender_ex
.Lfim_codigo_ex:

.Ldados_ex:
    .ascii  "ola do EL0"
    .space  OFF_DIAG - 10
    .ascii  "diagnostico de userspace"
    .space  OFF_NOME - OFF_DIAG - TAM_DIAG
    .ascii  "filho"
    .space  DADOS_NO_ARQUIVO - OFF_NOME - TAM_NOME
.Lfim_dados_ex:

.global programa_exemplo_fim
programa_exemplo_fim:

// --- o programa que o filho carrega ---------------------------------------
.balign 8
.global programa_filho_inicio
programa_filho_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_fi:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_FILHO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_fi - .Lelf_fi // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_fi - .Lcodigo_fi  // p_filesz
    .quad   .Lfim_codigo_fi - .Lcodigo_fi  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_fi:
    .ascii  "filho por exec"
    .space  OFF_CODIGO_FILHO - TAM_MSG_FILHO
    // A execucao comeca aqui: `e_entry` aponta 32 bytes adiante do segmento.
    mov     x0, #1
    movz    x1, #(VADDR_CODIGO & 0xFFFF)
    movk    x1, #((VADDR_CODIGO >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_CODIGO >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_MSG_FILHO
    mov     x8, #1
    svc     #0

    mov     x8, #0
    mov     x0, #24
    svc     #0
.Lprender_fi:
    b       .Lprender_fi
.Lfim_codigo_fi:

.global programa_filho_fim
programa_filho_fim:

// O leitor: dois caminhos no comeco do segmento de dados e um buffer logo
// depois, inteiro na `.bss` -- o carregador tem de entrega-lo zerado.
.set TAM_CAMINHO_LE,      13
.set OFF_DIRETORIO_LE,    16
.set TAM_DIRETORIO_LE,    6
.set DADOS_LE_NO_ARQUIVO, 24
.set OFF_BUFFER_LE,       32
.set TAM_BUFFER_LE,       64
.set DADOS_LE_NA_MEMORIA, OFF_BUFFER_LE + TAM_BUFFER_LE
.set VADDR_CAMINHO_LE,    VADDR_DADOS
.set VADDR_DIRETORIO_LE,  VADDR_DADOS + OFF_DIRETORIO_LE
.set VADDR_BUFFER_LE,     VADDR_DADOS + OFF_BUFFER_LE

// --- o leitor: abre, bifurca, le dos dois lados, escreve e fecha -----------
.balign 8
.global programa_leitor_inicio
programa_leitor_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
.Lelf_le:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                  // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_le - .Lelf_le              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_le - .Lcodigo_le       // p_filesz
    .quad   .Lfim_codigo_le - .Lcodigo_le       // p_memsz
    .quad   4096                                // p_align

    // segmento de dados: os caminhos vem do arquivo, o buffer nao. `p_memsz`
    // maior que `p_filesz` e o que pede os 64 bytes de buffer zerados.
    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_le - .Lelf_le               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_LE_NO_ARQUIVO                 // p_filesz
    .quad   DADOS_LE_NA_MEMORIA                 // p_memsz
    .quad   4096                                // p_align

.Lcodigo_le:
    // abrir(caminho, tamanho) -> descritor, ou negativo
    movz    x0, #(VADDR_CAMINHO_LE & 0xFFFF)
    movk    x0, #((VADDR_CAMINHO_LE >> 16) & 0xFFFF), lsl #16
    movk    x0, #((VADDR_CAMINHO_LE >> 32) & 0xFFFF), lsl #32
    mov     x1, #TAM_CAMINHO_LE
    mov     x8, #6
    svc     #0
    tbnz    x0, #63, .Lfalhou_le
    // O descritor fica num registrador que a chamada de sistema preserva: o
    // vetor de excecao salva e restaura x0..x30, menos o retorno.
    mov     x19, x0

    // bifurcar() com um arquivo ja aberto. O filho herda a tabela de
    // descritores -- e a leitura dele, logo abaixo, e o que prova isso: com
    // uma tabela nova o numero em x19 nao existiria do lado dele.
    mov     x8, #4
    svc     #0
    cbnz    x0, .Lpai_le

    // ler(descritor herdado, buffer, tamanho)
    mov     x0, x19
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_BUFFER_LE
    mov     x8, #7
    svc     #0
    cmp     x0, #0
    ble     .Lfalhou_le

    // sair(34): so o filho sai com este codigo.
    mov     x8, #0
    mov     x0, #34
    svc     #0

.Lpai_le:
    // ler(descritor, buffer, tamanho) -> quantos vieram
    //
    // O pai le do comeco, mesmo que o filho ja tenha lido: cada um levou a
    // propria copia da posicao. E o comportamento documentado na tabela, e
    // nao o do Unix, que compartilha a posicao entre pai e filho.
    mov     x0, x19
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_BUFFER_LE
    mov     x8, #7
    svc     #0
    cmp     x0, #0
    ble     .Lfalhou_le
    mov     x20, x0

    // escrever(SAIDA, buffer, quantos) -- e assim o que veio do disco
    // aparece do outro lado, escrito por um processo sem privilegio.
    mov     x2, x20
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x0, #1
    mov     x8, #1
    svc     #0

    // Escrever num descritor de arquivo tem de ser recusado: este kernel nao
    // tem escrita em arquivo, e aceitar mandaria o conteudo para o log como
    // se fosse uma mensagem.
    mov     x0, x19
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x2, #8
    mov     x8, #1
    svc     #0
    tbz     x0, #63, .Lfalhou_le

    // E ler num descritor de saida tambem: devolver zero fingiria um arquivo
    // vazio, e quem lesse ate o fim entenderia "acabou" em vez de "este
    // descritor nao le".
    mov     x0, #1
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_BUFFER_LE
    mov     x8, #7
    svc     #0
    tbz     x0, #63, .Lfalhou_le

    // Abrir um diretorio tem de ser recusado, e com o motivo certo: -10 e
    // "nao e arquivo", que e diferente de "nao encontrado". Um kernel que
    // devolvesse o segundo mandaria o programa procurar o erro no lugar
    // errado. `cmn` compara com o negativo: x0 + 10 == 0.
    movz    x0, #(VADDR_DIRETORIO_LE & 0xFFFF)
    movk    x0, #((VADDR_DIRETORIO_LE >> 16) & 0xFFFF), lsl #16
    movk    x0, #((VADDR_DIRETORIO_LE >> 32) & 0xFFFF), lsl #32
    mov     x1, #TAM_DIRETORIO_LE
    mov     x8, #6
    svc     #0
    cmn     x0, #10
    b.ne    .Lfalhou_le

    // fechar(descritor)
    mov     x0, x19
    mov     x8, #8
    svc     #0
    cbnz    x0, .Lfalhou_le

    // E ler de novo no mesmo numero. Tem de falhar: a vaga voltou para a
    // tabela. Sem esta conferencia, um `fechar` que nao fizesse nada passaria
    // -- e o programa nao teria como saber.
    mov     x0, x19
    movz    x1, #(VADDR_BUFFER_LE & 0xFFFF)
    movk    x1, #((VADDR_BUFFER_LE >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_BUFFER_LE >> 32) & 0xFFFF), lsl #32
    mov     x2, #TAM_BUFFER_LE
    mov     x8, #7
    svc     #0
    tbz     x0, #63, .Lfalhou_le

    // sair(33)
    mov     x8, #0
    mov     x0, #33
    svc     #0

.Lfalhou_le:
    mov     x8, #0
    mov     x0, #8
    svc     #0
.Lprender_le:
    b       .Lprender_le
.Lfim_codigo_le:

.Ldados_le:
    .ascii  "/saudacao.txt"
    .space  OFF_DIRETORIO_LE - TAM_CAMINHO_LE
    .ascii  "/dados"
    .space  DADOS_LE_NO_ARQUIVO - OFF_DIRETORIO_LE - TAM_DIRETORIO_LE
.Lfim_dados_le:

.global programa_leitor_fim
programa_leitor_fim:

// --- o invasor -------------------------------------------------------------
.balign 8
.global programa_invasor_inicio
programa_invasor_inicio:

// --- cabecalho ELF64 -------------------------------------------------------
// Os deslocamentos e tamanhos sao diferencas entre rotulos: o assembler os
// calcula, entao editar o programa nao desalinha o cabecalho.
.Lelf_inv:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO                // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                 // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                                    // PT_LOAD
    .long   5                                    // PF_R | PF_X
    .quad   .Lcodigo_inv - .Lelf_inv // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_inv - .Lcodigo_inv  // p_filesz
    .quad   .Lfim_codigo_inv - .Lcodigo_inv  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_inv:
    // Le o comeco da imagem do kernel, em 0x4008_0000.
    movz    x0, #0x4008, lsl #16
    ldr     x0, [x0]

    // Inalcancavel: a leitura acima e uma falha de protecao.
    mov     x8, #0
    mov     x0, #99
    svc     #0
.Lprender_inv:
    b       .Lprender_inv
.Lfim_codigo_inv:

.global programa_invasor_fim
programa_invasor_fim:
"#
);
