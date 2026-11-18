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
//! por ferramenta independente — `cargo xtask elf` roda o `llvm-readobj` sobre
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

/// Código de saída que o contador usaria se o contador de ciclos lhe fosse
/// legível no anel sem privilégio — ver [`bytes_do_contador`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_CONTADOR: i64 = 77;

/// Código de saída de um programa das exceções — ver [`bytes_da_excecao`] —
/// que sobreviveu à exceção que provoca: a culpa era do processo, e ele
/// tinha de morrer dela.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DA_EXCECAO: i64 = 66;

/// Onde o `#DB` do `int1` deixa o `rip`, a partir da entrada: depois da
/// instrução — o `#DB` é uma armadilha. O caso confere o `pc` da falha com
/// este número, e um programa editado que o mude reprova ali.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DEPOIS_DO_INT1: u64 = 1;

/// Onde o `#DB` do passo deixa o `rip`, a partir da entrada: depois da
/// instrução que segue o `popfq` que liga o `TF`.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DEPOIS_DO_PASSO: u64 = 11;

/// Onde o `#DB` do passo na chamada deixa o `rip`, a partir da entrada: na
/// instrução seguinte à `syscall`, no anel 3 — o processador confere o `TF`
/// depois do `sysretq`, como se a `syscall` tivesse acabado de rodar ali.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DEPOIS_DO_PASSO_NA_CHAMADA: u64 = 17;

/// Onde fica o `push` do programa da pilha não canônica, a partir da
/// entrada: o `#SS` é uma falha, e o `rip` é o da instrução.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const PUSH_DA_PILHA: u64 = 10;

/// Onde fica a carga do seletor — o `mov ds` ou o `mov ss` — nos programas
/// do LDT, do segmento ausente e da pilha ausente, a partir da entrada: a
/// falha é do `mov`, e o `rip` é o da instrução. Os casos conferem o `pc` da
/// falha com este número.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CARGA_DO_SELETOR: u64 = 5;

/// O código com que sai o programa do `lsl`: o `lsl` de um seletor do LDT
/// não falha — com o LDT nulo, ele só apaga o `ZF` —, e o processo segue até
/// a saída.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_LSL: i64 = 55;

/// Onde fica a `syscall` do programa do `mov ss`, a partir da entrada: no
/// QEMU do TCG, o `#DB` do passo chega no anel 3 logo depois do `mov ss`,
/// com o `rip` nela.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const NA_SYSCALL_DO_MOV_SS: u64 = 20;

/// Onde o `#DB` do programa do `mov ss` deixa o `rip` num processador, a
/// partir da entrada: o `mov ss` adia o passo até depois da `syscall`, o
/// `#DB` chega no anel 0 — e volta —, e o processo morre do passo no anel 3,
/// na volta da chamada, depois dela.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const DEPOIS_DO_MOV_SS: u64 = 22;

/// O código com que sai o programa do SIMD quando o registrador já tinha a
/// marca que ele deixa: o que o processo anterior deixou no núcleo chegou a
/// este — o canal entre processos. Sem ela, sai com zero.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_CANAL: i64 = 1;

/// Onde fica o `msr daif` do programa do `DAIF`, a partir da entrada.
#[cfg(target_arch = "aarch64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const MSR_DO_DAIF: u64 = 4;

/// Onde fica o `wfi` do programa do `wfi`, a partir da entrada.
#[cfg(target_arch = "aarch64")]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const WFI_DO_PROGRAMA: u64 = 4;

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

/// Código de saída do `filho` quando a troca de imagem lhe deixou o estado
/// da imagem anterior — as flags (o `RFLAGS` no x86, o `NZCV` no ARM) ou o
/// estado por fio (os seletores de dados no x86, o `TPIDR_EL0` no ARM) —, em
/// vez dos de um processo novo (o lote B4 do #448). Ele confere antes da
/// escrita, e sai com este no lugar de [`CODIGO_DO_FILHO`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_FILHO_SUJO: i64 = 25;

/// Código de saída do filho do `fork` do programa da herança
/// ([`Excecao::Heranca`]) quando ele não recebeu do pai o estado por fio.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_SEM_HERANCA: i64 = 26;

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

/// Código de saída do filho do programa que espera.
///
/// O pai sai com **este número mais um**, e é essa soma que prova a colheita:
/// um `esperar` que devolvesse o id certo sem trazer o código de saída faria
/// o pai sair com o veneno do slot, não com 52.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_FILHO_PACIENTE: i64 = 51;

/// Com o que o pai paciente sai quando tudo conferiu.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_PACIENTE: i64 = CODIGO_DO_FILHO_PACIENTE + 1;

/// Com o que o pai paciente sai quando alguma conferência falhou.
///
/// São três, e cada uma mataria uma parte diferente de `esperar`: o id
/// devolvido não é o do filho, a segunda espera **não** foi recusada, ou o
/// programa chegou onde não devia.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DE_FALHA_DO_PACIENTE: i64 = 9;

/// O que o slot do código de saída carrega antes de alguém escrever nele.
///
/// Veneno, e não zero: um `esperar` que devolvesse o id mas não escrevesse o
/// código faria o pai sair com `0 + 1`, que é um número plausível. Com 100 o
/// pai sairia com 101, que não se confunde com nada.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const VENENO_DO_SLOT: i64 = 100;

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
    #[link_name = "programa_paciente_inicio"]
    static PACIENTE_INICIO: u8;
    #[link_name = "programa_paciente_fim"]
    static PACIENTE_FIM: u8;
    #[link_name = "programa_orfao_inicio"]
    static ORFAO_INICIO: u8;
    #[link_name = "programa_orfao_fim"]
    static ORFAO_FIM: u8;
    #[link_name = "programa_contador_inicio"]
    static CONTADOR_INICIO: u8;
    #[link_name = "programa_contador_fim"]
    static CONTADOR_FIM: u8;
}

// Os programas das exceções do anel sem privilégio — ver
// [`bytes_da_excecao`].
#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    #[link_name = "programa_excecao_ud2_inicio"]
    static UD2_INICIO: u8;
    #[link_name = "programa_excecao_ud2_fim"]
    static UD2_FIM: u8;
    #[link_name = "programa_excecao_divisao_inicio"]
    static DIVISAO_INICIO: u8;
    #[link_name = "programa_excecao_divisao_fim"]
    static DIVISAO_FIM: u8;
    #[link_name = "programa_excecao_int1_inicio"]
    static INT1_INICIO: u8;
    #[link_name = "programa_excecao_int1_fim"]
    static INT1_FIM: u8;
    #[link_name = "programa_excecao_passo_inicio"]
    static PASSO_INICIO: u8;
    #[link_name = "programa_excecao_passo_fim"]
    static PASSO_FIM: u8;
    #[link_name = "programa_excecao_passo_na_chamada_inicio"]
    static PASSO_NA_CHAMADA_INICIO: u8;
    #[link_name = "programa_excecao_passo_na_chamada_fim"]
    static PASSO_NA_CHAMADA_FIM: u8;
    #[link_name = "programa_excecao_nt_inicio"]
    static NT_INICIO: u8;
    #[link_name = "programa_excecao_nt_fim"]
    static NT_FIM: u8;
    #[link_name = "programa_excecao_int3_inicio"]
    static INT3_INICIO: u8;
    #[link_name = "programa_excecao_int3_fim"]
    static INT3_FIM: u8;
    #[link_name = "programa_excecao_pilha_inicio"]
    static PILHA_INICIO: u8;
    #[link_name = "programa_excecao_pilha_fim"]
    static PILHA_FIM: u8;
    #[link_name = "programa_excecao_ldt_inicio"]
    static LDT_INICIO: u8;
    #[link_name = "programa_excecao_ldt_fim"]
    static LDT_FIM: u8;
    #[link_name = "programa_excecao_lsl_inicio"]
    static LSL_INICIO: u8;
    #[link_name = "programa_excecao_lsl_fim"]
    static LSL_FIM: u8;
    #[link_name = "programa_excecao_simd_inicio"]
    static SIMD_INICIO: u8;
    #[link_name = "programa_excecao_simd_fim"]
    static SIMD_FIM: u8;
    #[link_name = "programa_excecao_x87_inicio"]
    static X87_INICIO: u8;
    #[link_name = "programa_excecao_x87_fim"]
    static X87_FIM: u8;
    #[link_name = "programa_excecao_movss_inicio"]
    static MOVSS_INICIO: u8;
    #[link_name = "programa_excecao_movss_fim"]
    static MOVSS_FIM: u8;
    #[link_name = "programa_excecao_ausente_inicio"]
    static AUSENTE_INICIO: u8;
    #[link_name = "programa_excecao_ausente_fim"]
    static AUSENTE_FIM: u8;
    #[link_name = "programa_excecao_pilha_ausente_inicio"]
    static PILHA_AUSENTE_INICIO: u8;
    #[link_name = "programa_excecao_pilha_ausente_fim"]
    static PILHA_AUSENTE_FIM: u8;
    #[link_name = "programa_excecao_sysenter_inicio"]
    static SYSENTER_INICIO: u8;
    #[link_name = "programa_excecao_sysenter_fim"]
    static SYSENTER_FIM: u8;
    #[link_name = "programa_excecao_canal_fs_inicio"]
    static CANAL_FS_INICIO: u8;
    #[link_name = "programa_excecao_canal_fs_fim"]
    static CANAL_FS_FIM: u8;
    #[link_name = "programa_excecao_canal_seletores_inicio"]
    static CANAL_SELETORES_INICIO: u8;
    #[link_name = "programa_excecao_canal_seletores_fim"]
    static CANAL_SELETORES_FIM: u8;
    #[link_name = "programa_excecao_seletores_receptor_inicio"]
    static SELETORES_RECEPTOR_INICIO: u8;
    #[link_name = "programa_excecao_seletores_receptor_fim"]
    static SELETORES_RECEPTOR_FIM: u8;
    #[link_name = "programa_excecao_seletores_emissor_inicio"]
    static SELETORES_EMISSOR_INICIO: u8;
    #[link_name = "programa_excecao_seletores_emissor_fim"]
    static SELETORES_EMISSOR_FIM: u8;
    #[link_name = "programa_excecao_str_inicio"]
    static STR_INICIO: u8;
    #[link_name = "programa_excecao_str_fim"]
    static STR_FIM: u8;
    #[link_name = "programa_excecao_sldt_inicio"]
    static SLDT_INICIO: u8;
    #[link_name = "programa_excecao_sldt_fim"]
    static SLDT_FIM: u8;
    #[link_name = "programa_excecao_smsw_inicio"]
    static SMSW_INICIO: u8;
    #[link_name = "programa_excecao_smsw_fim"]
    static SMSW_FIM: u8;
    #[link_name = "programa_excecao_sgdt_inicio"]
    static SGDT_INICIO: u8;
    #[link_name = "programa_excecao_sgdt_fim"]
    static SGDT_FIM: u8;
    #[link_name = "programa_excecao_sidt_inicio"]
    static SIDT_INICIO: u8;
    #[link_name = "programa_excecao_sidt_fim"]
    static SIDT_FIM: u8;
    #[link_name = "programa_excecao_fwait_inicio"]
    static FWAIT_INICIO: u8;
    #[link_name = "programa_excecao_fwait_fim"]
    static FWAIT_FIM: u8;
}

// Os programas das exceções do EL0 — ver [`bytes_da_excecao`].
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    #[link_name = "programa_excecao_brk_estouro_inicio"]
    static BRK_ESTOURO_INICIO: u8;
    #[link_name = "programa_excecao_brk_estouro_fim"]
    static BRK_ESTOURO_FIM: u8;
    #[link_name = "programa_excecao_brk_borda_inicio"]
    static BRK_BORDA_INICIO: u8;
    #[link_name = "programa_excecao_brk_borda_fim"]
    static BRK_BORDA_FIM: u8;
    #[link_name = "programa_excecao_brk_inicio"]
    static BRK_INICIO: u8;
    #[link_name = "programa_excecao_brk_fim"]
    static BRK_FIM: u8;
    #[link_name = "programa_excecao_simd_inicio"]
    static SIMD_INICIO: u8;
    #[link_name = "programa_excecao_simd_fim"]
    static SIMD_FIM: u8;
    #[link_name = "programa_excecao_daif_inicio"]
    static DAIF_INICIO: u8;
    #[link_name = "programa_excecao_daif_fim"]
    static DAIF_FIM: u8;
    #[link_name = "programa_excecao_wfi_inicio"]
    static WFI_INICIO: u8;
    #[link_name = "programa_excecao_wfi_fim"]
    static WFI_FIM: u8;
    #[link_name = "programa_excecao_canal_tpidr_inicio"]
    static CANAL_TPIDR_INICIO: u8;
    #[link_name = "programa_excecao_canal_tpidr_fim"]
    static CANAL_TPIDR_FIM: u8;
    #[link_name = "programa_excecao_tpidr_receptor_inicio"]
    static TPIDR_RECEPTOR_INICIO: u8;
    #[link_name = "programa_excecao_tpidr_receptor_fim"]
    static TPIDR_RECEPTOR_FIM: u8;
    #[link_name = "programa_excecao_tpidr_emissor_inicio"]
    static TPIDR_EMISSOR_INICIO: u8;
    #[link_name = "programa_excecao_tpidr_emissor_fim"]
    static TPIDR_EMISSOR_FIM: u8;
    #[link_name = "programa_excecao_mdccsr_inicio"]
    static MDCCSR_INICIO: u8;
    #[link_name = "programa_excecao_mdccsr_fim"]
    static MDCCSR_FIM: u8;
}

// Os programas das exceções das duas arquiteturas, com o mesmo nome nos dois
// blocos de assembly — ver [`bytes_da_excecao`].
unsafe extern "C" {
    #[link_name = "programa_excecao_registradores_inicio"]
    static REGISTRADORES_INICIO: u8;
    #[link_name = "programa_excecao_registradores_fim"]
    static REGISTRADORES_FIM: u8;
    #[link_name = "programa_excecao_heranca_inicio"]
    static HERANCA_INICIO: u8;
    #[link_name = "programa_excecao_heranca_fim"]
    static HERANCA_FIM: u8;
    #[link_name = "programa_excecao_troca_com_flags_inicio"]
    static TROCA_COM_FLAGS_INICIO: u8;
    #[link_name = "programa_excecao_troca_com_flags_fim"]
    static TROCA_COM_FLAGS_FIM: u8;
}

/// Os programas das exceções que um processo provoca — os lotes B2 e B3 do
/// #448. Cada um provoca a dele na entrada, ou depois do mínimo que ela
/// pede, e tem de morrer dela: uma exceção vinda do anel sem privilégio é
/// culpa do processo, e não do kernel. O do `NT` não provoca nenhuma: troca
/// de imagem e sai pelo `filho`; o do `lsl`, só no x86, também não: sai
/// com `CODIGO_DO_LSL`. Se seguir, sai com [`CODIGO_DA_EXCECAO`] — menos o do
/// SIMD, que sai com zero, ou com [`CODIGO_DO_CANAL`] se o registrador já
/// tinha a marca de quem rodou antes no núcleo.
///
/// O lote B4 acrescentou os do estado por fio — o `TPIDR_EL0` no ARM e os
/// seletores de dados no x86 —, que não provocam exceção nenhuma: os do
/// canal saem com zero, ou com [`CODIGO_DO_CANAL`]; o receptor do par morre
/// de uma falha se o registrador dele mudou, e o emissor sai com zero; os
/// registradores da entrada saem com zero, ou com 1; e a herança sai com o
/// código do `filho`, [`CODIGO_DO_FILHO_SUJO`] ou [`CODIGO_SEM_HERANCA`]; e a
/// troca com as flags ligadas, com o do `filho` ou [`CODIGO_DO_FILHO_SUJO`].
/// E os que morrem: o `str`, o `sldt`, o `smsw`, o `sgdt` e o `sidt` do
/// UMIP, o `fwait` e o canal do depurador do ARM.
/// Não estão em `/bin`: só a suíte os roda.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Excecao {
    /// `ud2`: o `#UD`.
    #[cfg(target_arch = "x86_64")]
    Ud2,
    /// A divisão por zero: o `#DE`.
    #[cfg(target_arch = "x86_64")]
    Divisao,
    /// O `int1` — o `icebp` —: o `#DB`, sem a conferência do DPL.
    #[cfg(target_arch = "x86_64")]
    Int1,
    /// O `TF` ligado pelo `popfq`, e um `nop`: o `#DB` do passo.
    #[cfg(target_arch = "x86_64")]
    Passo,
    /// O `TF` ligado, e a `syscall`: o `#DB` no anel 3, na volta.
    #[cfg(target_arch = "x86_64")]
    PassoNaChamada,
    /// O `NT` ligado, e chamadas — `ceder`, `id` e a troca de imagem pelo
    /// `filho`, que sai com o código dele.
    #[cfg(target_arch = "x86_64")]
    Nt,
    /// `int3`: o `#GP` do portão de DPL 0.
    #[cfg(target_arch = "x86_64")]
    Int3,
    /// O `push` com o `rsp` não canônico: o `#SS`.
    #[cfg(target_arch = "x86_64")]
    Pilha,
    /// O `mov ds` com o seletor 0x0F, do LDT: o `#GP` do LDT nulo.
    #[cfg(target_arch = "x86_64")]
    Ldt,
    /// O `lsl` com o seletor 0x0F, do LDT: nenhuma falha, e a saída com
    /// [`CODIGO_DO_LSL`].
    #[cfg(target_arch = "x86_64")]
    Lsl,
    /// O `movq` do `xmm0`: o `#NM` do `CR0.TS` — e, sem ele, o canal.
    #[cfg(target_arch = "x86_64")]
    Simd,
    /// O `fld1` do x87: o `#NM` do `CR0.TS`.
    #[cfg(target_arch = "x86_64")]
    X87,
    /// O `TF` ligado, o `mov ss` e a `syscall`: o passo adiado do
    /// CVE-2018-8897.
    #[cfg(target_arch = "x86_64")]
    MovSs,
    /// O `mov ds` com o seletor 0x1B, cujo descritor o caso marca ausente:
    /// o `#NP`.
    #[cfg(target_arch = "x86_64")]
    Ausente,
    /// O `mov ss` com o mesmo seletor: o `#SS`.
    #[cfg(target_arch = "x86_64")]
    PilhaAusente,
    /// `sysenter`: o `#GP` do `IA32_SYSENTER_CS` em zero, num Intel; o
    /// `#UD`, num AMD — e no QEMU do TCG.
    #[cfg(target_arch = "x86_64")]
    Sysenter,
    /// `brk #0xe5`, o imediato do estouro de propósito.
    #[cfg(target_arch = "aarch64")]
    BrkDoEstouro,
    /// `brk #0xe6`, o do estouro na borda.
    #[cfg(target_arch = "aarch64")]
    BrkDaBorda,
    /// `brk #0`.
    #[cfg(target_arch = "aarch64")]
    Brk,
    /// O `fmov` do `d0`: a classe 0x07 do `CPACR_EL1` em zero — e, sem
    /// ele, o canal.
    #[cfg(target_arch = "aarch64")]
    Simd,
    /// O `msr daif` que mascara as IRQs: a armadilha do `SCTLR_EL1.UMA`
    /// desligado.
    #[cfg(target_arch = "aarch64")]
    Daif,
    /// O `wfi`: a armadilha do `SCTLR_EL1.nTWI` desligado.
    #[cfg(target_arch = "aarch64")]
    Wfi,
    /// O `FS` que o processo anterior deixou no núcleo, e a marca para o
    /// seguinte: sai com [`CODIGO_DO_CANAL`] se ela já estava lá.
    #[cfg(target_arch = "x86_64")]
    CanalFs,
    /// O mesmo, com o `DS`, o `ES`, o `FS` e o `GS`.
    #[cfg(target_arch = "x86_64")]
    CanalSeletores,
    /// As quatro marcas, conferidas a cada uma de 64 cessões: o `ud2` se
    /// alguma mudou.
    #[cfg(target_arch = "x86_64")]
    SeletoresReceptor,
    /// As outras quatro marcas, a cada uma de 64 cessões.
    #[cfg(target_arch = "x86_64")]
    SeletoresEmissor,
    /// O `str` do anel 3: o `#GP(0)` do UMIP.
    #[cfg(target_arch = "x86_64")]
    Str,
    /// O `sldt` do anel 3: o `#GP(0)` do UMIP.
    #[cfg(target_arch = "x86_64")]
    Sldt,
    /// O `smsw` do anel 3: o `#GP(0)` do UMIP.
    #[cfg(target_arch = "x86_64")]
    Smsw,
    /// O `sgdt` do anel 3: o `#GP(0)` do UMIP.
    #[cfg(target_arch = "x86_64")]
    Sgdt,
    /// O `sidt` do anel 3: o `#GP(0)` do UMIP.
    #[cfg(target_arch = "x86_64")]
    Sidt,
    /// O `fwait`: o `#NM` do `CR0.MP` com o `CR0.TS`.
    #[cfg(target_arch = "x86_64")]
    Fwait,
    /// O `TPIDR_EL0` que o processo anterior deixou no núcleo, e a marca
    /// para o seguinte: sai com [`CODIGO_DO_CANAL`] se ela já estava lá.
    #[cfg(target_arch = "aarch64")]
    CanalTpidr,
    /// A marca no `TPIDR_EL0`, conferida a cada uma de 64 cessões: o `brk
    /// #1` se ela mudou.
    #[cfg(target_arch = "aarch64")]
    TpidrReceptor,
    /// Outra marca no `TPIDR_EL0`, a cada uma de 64 cessões.
    #[cfg(target_arch = "aarch64")]
    TpidrEmissor,
    /// A leitura do `MDCCSR_EL0`: a armadilha do `MDSCR_EL1.TDCC`.
    #[cfg(target_arch = "aarch64")]
    Mdccsr,
    /// Os registradores na primeira entrada — os gerais, e os seletores de
    /// dados no x86, o `TPIDR_EL0` e o `TPIDRRO_EL0` no ARM —: sai com 1 se
    /// algum não veio zerado.
    Registradores,
    /// O estado por fio marcado, o `fork`, a conferência no filho e a troca
    /// de imagem pelo `filho`, que o confere zerado.
    Heranca,
    /// As flags ligadas — o `DF` e o `CF` no x86, o `NZCV` no ARM — e a troca
    /// de imagem pelo `filho`, que as confere as de um processo novo.
    TrocaComFlags,
}

/// A imagem ELF do programa da exceção `e` — ver [`Excecao`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_da_excecao(e: Excecao) -> &'static [u8] {
    // SAFETY: ver `entre`; cada par delimita o seu programa.
    unsafe {
        match e {
            #[cfg(target_arch = "x86_64")]
            Excecao::Ud2 => entre(&raw const UD2_INICIO, &raw const UD2_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Divisao => entre(&raw const DIVISAO_INICIO, &raw const DIVISAO_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Int1 => entre(&raw const INT1_INICIO, &raw const INT1_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Passo => entre(&raw const PASSO_INICIO, &raw const PASSO_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::PassoNaChamada => entre(
                &raw const PASSO_NA_CHAMADA_INICIO,
                &raw const PASSO_NA_CHAMADA_FIM,
            ),
            #[cfg(target_arch = "x86_64")]
            Excecao::Nt => entre(&raw const NT_INICIO, &raw const NT_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Int3 => entre(&raw const INT3_INICIO, &raw const INT3_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Pilha => entre(&raw const PILHA_INICIO, &raw const PILHA_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Ldt => entre(&raw const LDT_INICIO, &raw const LDT_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Lsl => entre(&raw const LSL_INICIO, &raw const LSL_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Simd => entre(&raw const SIMD_INICIO, &raw const SIMD_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::X87 => entre(&raw const X87_INICIO, &raw const X87_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::MovSs => entre(&raw const MOVSS_INICIO, &raw const MOVSS_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Ausente => entre(&raw const AUSENTE_INICIO, &raw const AUSENTE_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::PilhaAusente => entre(
                &raw const PILHA_AUSENTE_INICIO,
                &raw const PILHA_AUSENTE_FIM,
            ),
            #[cfg(target_arch = "x86_64")]
            Excecao::Sysenter => entre(&raw const SYSENTER_INICIO, &raw const SYSENTER_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::BrkDoEstouro => {
                entre(&raw const BRK_ESTOURO_INICIO, &raw const BRK_ESTOURO_FIM)
            }
            #[cfg(target_arch = "aarch64")]
            Excecao::BrkDaBorda => entre(&raw const BRK_BORDA_INICIO, &raw const BRK_BORDA_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::Brk => entre(&raw const BRK_INICIO, &raw const BRK_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::Simd => entre(&raw const SIMD_INICIO, &raw const SIMD_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::Daif => entre(&raw const DAIF_INICIO, &raw const DAIF_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::Wfi => entre(&raw const WFI_INICIO, &raw const WFI_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::CanalFs => entre(&raw const CANAL_FS_INICIO, &raw const CANAL_FS_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::CanalSeletores => entre(
                &raw const CANAL_SELETORES_INICIO,
                &raw const CANAL_SELETORES_FIM,
            ),
            #[cfg(target_arch = "x86_64")]
            Excecao::SeletoresReceptor => entre(
                &raw const SELETORES_RECEPTOR_INICIO,
                &raw const SELETORES_RECEPTOR_FIM,
            ),
            #[cfg(target_arch = "x86_64")]
            Excecao::SeletoresEmissor => entre(
                &raw const SELETORES_EMISSOR_INICIO,
                &raw const SELETORES_EMISSOR_FIM,
            ),
            #[cfg(target_arch = "x86_64")]
            Excecao::Str => entre(&raw const STR_INICIO, &raw const STR_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Sldt => entre(&raw const SLDT_INICIO, &raw const SLDT_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Smsw => entre(&raw const SMSW_INICIO, &raw const SMSW_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Sgdt => entre(&raw const SGDT_INICIO, &raw const SGDT_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Sidt => entre(&raw const SIDT_INICIO, &raw const SIDT_FIM),
            #[cfg(target_arch = "x86_64")]
            Excecao::Fwait => entre(&raw const FWAIT_INICIO, &raw const FWAIT_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::CanalTpidr => entre(&raw const CANAL_TPIDR_INICIO, &raw const CANAL_TPIDR_FIM),
            #[cfg(target_arch = "aarch64")]
            Excecao::TpidrReceptor => entre(
                &raw const TPIDR_RECEPTOR_INICIO,
                &raw const TPIDR_RECEPTOR_FIM,
            ),
            #[cfg(target_arch = "aarch64")]
            Excecao::TpidrEmissor => entre(
                &raw const TPIDR_EMISSOR_INICIO,
                &raw const TPIDR_EMISSOR_FIM,
            ),
            #[cfg(target_arch = "aarch64")]
            Excecao::Mdccsr => entre(&raw const MDCCSR_INICIO, &raw const MDCCSR_FIM),
            Excecao::Registradores => entre(
                &raw const REGISTRADORES_INICIO,
                &raw const REGISTRADORES_FIM,
            ),
            Excecao::Heranca => entre(&raw const HERANCA_INICIO, &raw const HERANCA_FIM),
            Excecao::TrocaComFlags => entre(
                &raw const TROCA_COM_FLAGS_INICIO,
                &raw const TROCA_COM_FLAGS_FIM,
            ),
        }
    }
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

/// A imagem ELF do programa que bifurca e **espera** o filho.
///
/// Existe porque `esperar` é a única chamada deste kernel que bloqueia, e
/// bloquear é o tipo de coisa que funciona por acidente: um pai que
/// simplesmente perguntasse em laço até achar o filho passaria em qualquer
/// teste que só olhasse o código de saída.
///
/// Por isso ele confere cinco coisas, e sai com
/// [`CODIGO_DE_FALHA_DO_PACIENTE`] se qualquer uma falhar:
///
/// 0. um ponteiro inválido é recusado **sem** consumir o filho — a colheita
///    é destrutiva, e conferir depois dela trocaria a resposta pelo erro;
/// 1. o id devolvido por `esperar` é o do filho que `bifurcar` devolveu;
/// 2. o código de saída chegou ao slot — o pai sai com ele **mais um**, e o
///    slot começa envenenado com [`VENENO_DO_SLOT`];
/// 3. a segunda espera é **recusada**, porque o filho já foi colhido. Sem
///    esta, um `esperar` que esquecesse de marcar a colheita devolveria o
///    mesmo filho para sempre.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_do_paciente() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const PACIENTE_INICIO, &raw const PACIENTE_FIM) }
}

/// Código com que o pai do órfão sai quando o desfecho conferiu.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_ORFAO: i64 = 53;

/// Código com que o órfão sai quando alguma conferência dele falhou.
///
/// Serve também para o filho: se ele **sobreviver** à leitura da memória do
/// kernel e chegar ao `sair`, é este o número que aparece — e ele denuncia
/// uma proteção que não protege, não uma espera que não funciona.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DE_FALHA_DO_ORFAO: i64 = 10;

/// A imagem ELF do programa cujo filho morre de falha.
///
/// # O que ele prova que o paciente não prova
///
/// Que o pai distingue "o filho saiu com zero" de "o filho foi morto". Os
/// dois eram a mesma coisa até a segunda palavra do desfecho existir: quem
/// morre de falha de página nunca chega a `sair`, não tem código, e o
/// kernel escrevia zero — o código de saída mais comum que existe.
///
/// O filho aqui lê a memória do kernel, que é o mesmo que o `invasor` faz,
/// e morre por isso. O pai espera e exige `MORTO`. Se o kernel voltar a
/// inventar um zero, este é o único caso que reprova.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_do_orfao() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const ORFAO_INICIO, &raw const ORFAO_FIM) }
}

/// A imagem ELF do programa que lê o contador de ciclos — o `rdtsc` no x86,
/// o `CNTVCT_EL0` no ARM — na primeira instrução, a da entrada.
///
/// Existe para provar que o contador não é um relógio do programa: o
/// relógio dele é o `system.uptime`, decidido pelo gate. O kernel tira o
/// contador do anel sem privilégio em todo núcleo — o `CR4.TSD` no x86, o
/// `CNTKCTL_EL1` e o `PMUSERENR_EL0` no ARM (o #451) —, e a leitura é uma
/// falha de proteção, que mata o processo como uma instrução privilegiada.
/// Se ele seguir em frente, sai com [`CODIGO_DO_CONTADOR`]: a leitura
/// passou. Não está em `/bin`: só a suíte o roda.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_do_contador() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const CONTADOR_INICIO, &raw const CONTADOR_FIM) }
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
    .short  3                 // e_phnum
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

    // o manifesto: uma nota, que nao se carrega — o kernel a le da imagem
    .long   4                                   // PT_NOTE
    .long   4                                   // PF_R
    .quad   .Lnota_ex - .Lelf_ex              // p_offset
    .quad   0                                   // p_vaddr: nao se carrega
    .quad   0                                   // p_paddr
    .quad   .Lfim_nota_ex - .Lnota_ex         // p_filesz
    .quad   .Lfim_nota_ex - .Lnota_ex         // p_memsz
    .quad   4                                   // p_align

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

// O manifesto, no formato de `protocolo::usuario::manifesto`: o que este
// programa exerce, e nada mais.
.balign 4
.Lnota_ex:
    .long   5                                   // tamanho do dono
    .long   .Lfim_texto_ex - .Ltexto_ex       // tamanho do conteudo
    .long   1                                   // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_ex:
    .ascii  "duke-manifesto 1\nnome exemplo\npermite process.run\n"
.Lfim_texto_ex:
    .balign 4
.Lfim_nota_ex:

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
    //
    // A troca de imagem entrega as flags de um processo novo -- so o IF e o
    // bit 1, 0x202, as do `entrar` -- e os seletores de dados nulos: o
    // programa que entra nao tem direito ao estado do que saiu (o lote B4 do
    // #448). Se algum veio com o da imagem anterior, sai com 25, antes da
    // escrita que os casos da troca de imagem procuram. As flags primeiro,
    // antes de qualquer instrucao que as mude; o `pushfq` usa a pilha que o
    // carregador deu.
    pushfq
    pop     rax
    cmp     rax, 0x202
    jne     .Lsujo_fi
    mov     eax, ds
    mov     ecx, es
    or      eax, ecx
    mov     ecx, fs
    or      eax, ecx
    mov     ecx, gs
    or      eax, ecx
    jnz     .Lsujo_fi
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
.Lsujo_fi:
    mov     eax, 0
    mov     edi, 25
    syscall
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
    .short  3                        // e_phnum
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

    // o manifesto: uma nota, que nao se carrega — o kernel a le da imagem
    .long   4                                   // PT_NOTE
    .long   4                                   // PF_R
    .quad   .Lnota_le - .Lelf_le              // p_offset
    .quad   0                                   // p_vaddr: nao se carrega
    .quad   0                                   // p_paddr
    .quad   .Lfim_nota_le - .Lnota_le         // p_filesz
    .quad   .Lfim_nota_le - .Lnota_le         // p_memsz
    .quad   4                                   // p_align

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

// O manifesto, no formato de `protocolo::usuario::manifesto`: o que este
// programa exerce, e nada mais.
.balign 4
.Lnota_le:
    .long   5                                   // tamanho do dono
    .long   .Lfim_texto_le - .Ltexto_le       // tamanho do conteudo
    .long   1                                   // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_le:
    .ascii  "duke-manifesto 1\nnome leitor\npermite fs.read\n"
.Lfim_texto_le:
    .balign 4
.Lfim_nota_le:

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

// --- o contador: le o contador de ciclos no anel 3 --------------------------
//
// A primeira instrucao, na entrada, e o `rdtsc`. Com o `CR4.TSD` ligado, ela
// e privilegiada: falha de protecao no anel 3, e o processo morre ali.
.balign 8
.global programa_contador_inicio
programa_contador_inicio:

.Lelf_cont:
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
    .quad   .Lcodigo_cont - .Lelf_cont // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_cont - .Lcodigo_cont  // p_filesz
    .quad   .Lfim_codigo_cont - .Lcodigo_cont  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_cont:
    rdtsc

    // Inalcancavel: com o contador fora do anel 3, a leitura acima e uma
    // falha de protecao. Se chegarmos aqui, ela passou.
    mov     eax, 0
    mov     edi, 77
    syscall
.Lprender_cont:
    jmp     .Lprender_cont
.Lfim_codigo_cont:

.global programa_contador_fim
programa_contador_fim:

// --- o paciente: bifurca, espera o filho e sai com o codigo dele -----------
//
// Dois segmentos: o codigo, e oito bytes gravaveis onde `esperar` deposita o
// codigo de saida do filho. O slot comeca envenenado -- se ninguem escrever
// nele, o pai sai com o veneno mais um, que nao se confunde com nada.
.set OFF_CODIGO_PACIENTE, 32
.set VADDR_SLOT_PA,       VADDR_DADOS
.set VADDR_VALEU_PA,      VADDR_DADOS + 8
.set DADOS_PA,            16

.balign 8
.global programa_paciente_inicio
programa_paciente_inicio:

.Lelf_pa:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_PACIENTE   // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // codigo: leitura e execucao
    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_pa - .Lelf_pa              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_pa - .Lcodigo_pa       // p_filesz
    .quad   .Lfim_codigo_pa - .Lcodigo_pa       // p_memsz
    .quad   4096                                // p_align

    // dados: leitura e escrita, o slot do codigo de saida
    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_pa - .Lelf_pa               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_PA                            // p_filesz
    .quad   DADOS_PA                            // p_memsz
    .quad   4096                                // p_align

.Lcodigo_pa:
    .space  OFF_CODIGO_PACIENTE
    // bifurcar()
    mov     eax, 4
    syscall
    test    rax, rax
    jz      .Lfilho_pa

    // O pai guarda o id do filho em RBX, que o quadro da chamada preserva.
    mov     rbx, rax

    // Um ponteiro invalido tem de ser recusado **sem** custar o filho: o
    // endereco 1 esta fora da faixa do usuario. Se a colheita acontecesse
    // antes da conferencia, esta chamada consumiria o filho e a seguinte
    // nao acharia mais ninguem.
    xor     edi, edi
    mov     esi, 1
    mov     eax, 9
    syscall
    test    rax, rax
    jns     .Lfalhou_pa

    // esperar(0, &slot): qualquer filho, com o codigo de saida no slot.
    xor     edi, edi
    movabs  rsi, offset VADDR_SLOT_PA
    mov     eax, 9
    syscall

    // 1. o id colhido tem de ser o do filho
    cmp     rax, rbx
    jne     .Lfalhou_pa

    // 2. a segunda espera tem de ser recusada: o filho ja foi colhido
    xor     edi, edi
    xor     esi, esi
    mov     eax, 9
    syscall
    test    rax, rax
    jns     .Lfalhou_pa

    // 3. o desfecho tem de dizer que o filho saiu por `sair`. Sem isto, um
    //    kernel que escrevesse zero para quem foi morto passaria batido:
    //    zero e um codigo de saida perfeitamente legitimo.
    movabs  rax, offset VADDR_VALEU_PA
    mov     rax, [rax]
    cmp     rax, 1
    jne     .Lfalhou_pa

    // 4. sair com o codigo do filho mais um
    movabs  rax, offset VADDR_SLOT_PA
    mov     rdi, [rax]
    inc     rdi
    mov     eax, 0
    syscall

.Lfilho_pa:
    mov     eax, 0
    mov     edi, 51
    syscall

.Lfalhou_pa:
    mov     eax, 0
    mov     edi, 9
    syscall
.Lprender_pa:
    jmp     .Lprender_pa
.Lfim_codigo_pa:

.Ldados_pa:
    .quad   100                      // o veneno do codigo
    .quad   -1                       // o veneno do "vale?"
.Lfim_dados_pa:

.global programa_paciente_fim
programa_paciente_fim:

// --- o orfao: o filho morre de falha, e o pai precisa saber disso ---------
//
// Mesma forma do paciente, com uma diferenca no filho: em vez de sair, ele
// le a memoria do kernel e e morto. O que se afirma e do lado do pai -- que
// o desfecho diga `MORTO`, e nao um codigo de saida inventado.
.set OFF_CODIGO_ORFAO, 32
.set VADDR_SLOT_OR,    VADDR_DADOS
.set VADDR_VALEU_OR,   VADDR_DADOS + 8
.set DADOS_OR,         16

.balign 8
.global programa_orfao_inicio
programa_orfao_inicio:

.Lelf_or:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_ORFAO      // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_or - .Lelf_or              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_or - .Lcodigo_or       // p_filesz
    .quad   .Lfim_codigo_or - .Lcodigo_or       // p_memsz
    .quad   4096                                // p_align

    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_or - .Lelf_or               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_OR                            // p_filesz
    .quad   DADOS_OR                            // p_memsz
    .quad   4096                                // p_align

.Lcodigo_or:
    .space  OFF_CODIGO_ORFAO
    // bifurcar()
    mov     eax, 4
    syscall
    test    rax, rax
    jz      .Lfilho_or

    // esperar(0, &slot)
    xor     edi, edi
    movabs  rsi, offset VADDR_SLOT_OR
    mov     eax, 9
    syscall
    test    rax, rax
    js      .Lfalhou_or

    // O desfecho tem de dizer MORTO (0). Este e o ponto do programa: um
    // kernel que escrevesse "saiu com 0" para quem foi morto reprovaria
    // aqui, e em nenhum outro lugar.
    movabs  rax, offset VADDR_VALEU_OR
    mov     rax, [rax]
    test    rax, rax
    jnz     .Lfalhou_or

    mov     eax, 0
    mov     edi, 53
    syscall

.Lfilho_or:
    // Le o comeco da imagem do kernel. E uma falha de protecao, e o filho
    // morre sem nunca chamar `sair`.
    movabs  rax, 0xffff800000000000
    mov     rax, [rax]
    // Inalcancavel.
    mov     eax, 0
    mov     edi, 10
    syscall

.Lfalhou_or:
    mov     eax, 0
    mov     edi, 10
    syscall
.Lprender_or:
    jmp     .Lprender_or
.Lfim_codigo_or:

.Ldados_or:
    .quad   100                      // o veneno do codigo
    .quad   -1                       // o veneno do "vale?"
.Lfim_dados_or:

.global programa_orfao_fim
programa_orfao_fim:

// --- as excecoes do anel 3: um programa por excecao ------------------------
//
// O lote B2 do #448. Cada programa provoca uma excecao do processador logo na
// entrada -- ou depois do minimo que ela pede -- e morre dela: a culpa e do
// processo, e nao do kernel. Se seguir, sai com 66, que a suite reconhece
// como "a excecao nao matou". Um cabecalho e um segmento so, de leitura e
// execucao; a pilha e a que o carregador da.
//
// Os deslocamentos que a suite confere -- onde a excecao deixa o `rip` --
// sao os das constantes de `exemplo` (`DEPOIS_DO_INT1` e as outras): um
// programa editado que os mude reprova o caso dele, que diz o `pc` que achou.
// O montador nao os confere mais: o `.if` com a diferenca de dois rotulos nao
// e absoluto no passo do LTO do release, que le este assembly antes de haver
// leiaute, e o release dizia erros que nao eram (o lote B4 do #448).
.macro ELF_DE_UM_SEGMENTO elf, codigo, fim
\elf:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   \codigo - \elf           // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   \fim - \codigo           // p_filesz
    .quad   \fim - \codigo           // p_memsz
    .quad   4096                     // p_align
.endm

// A saida de quem sobreviveu a excecao: sair(66), e o laco que nao volta.
.macro SOBREVIVEU rotulo
    mov     eax, 0
    mov     edi, 66
    syscall
\rotulo:
    jmp     \rotulo
.endm

// `ud2`: a instrucao invalida (#UD).
.balign 8
.global programa_excecao_ud2_inicio
programa_excecao_ud2_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_ud2, .Lcodigo_ud2, .Lfim_codigo_ud2
.Lcodigo_ud2:
    ud2
    SOBREVIVEU .Lprender_ud2
.Lfim_codigo_ud2:
.global programa_excecao_ud2_fim
programa_excecao_ud2_fim:

// A divisao por zero (#DE): o divisor e um zero do proprio codigo, e a
// primeira instrucao ja divide -- os registradores da entrada nao sao do
// programa.
.balign 8
.global programa_excecao_divisao_inicio
programa_excecao_divisao_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_div, .Lcodigo_div, .Lfim_codigo_div
.Lcodigo_div:
    div     qword ptr [rip + .Lzero_div]
    SOBREVIVEU .Lprender_div
    .balign 8
.Lzero_div:
    .quad   0
.Lfim_codigo_div:
.global programa_excecao_divisao_fim
programa_excecao_divisao_fim:

// `int1` -- o `icebp`, 0xF1 --, que o processador entrega como #DB sem
// conferir o DPL do portao: um processo o alcanca de qualquer jeito. O #DB e
// uma armadilha, e o `rip` fica depois da instrucao.
.balign 8
.global programa_excecao_int1_inicio
programa_excecao_int1_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_int1, .Lcodigo_int1, .Lfim_codigo_int1
.Lcodigo_int1:
    .byte   0xF1
.Ldepois_int1:
    SOBREVIVEU .Lprender_int1
.Lfim_codigo_int1:
.global programa_excecao_int1_fim
programa_excecao_int1_fim:

// O `TF` ligado pelo proprio processo: o `popfq` o liga, a instrucao seguinte
// roda, e o #DB chega depois dela.
.balign 8
.global programa_excecao_passo_inicio
programa_excecao_passo_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_passo, .Lcodigo_passo, .Lfim_codigo_passo
.Lcodigo_passo:
    pushfq
    or      qword ptr [rsp], 0x100
    popfq
    nop
.Ldepois_passo:
    nop
    SOBREVIVEU .Lprender_passo
.Lfim_codigo_passo:
.global programa_excecao_passo_fim
programa_excecao_passo_fim:

// O `TF` ligado, e a instrucao seguinte e a `syscall`. O `SFMask` o apaga na
// entrada do anel 0 -- sem isso, o #DB chegaria ao kernel antes da troca de
// pilha, com o `rsp` do processo --; a chamada `id` roda inteira, o
// `sysretq` devolve o `TF` com as flags do processo, e o #DB chega no anel
// 3 na volta, como se a `syscall` tivesse acabado de rodar ali: o `rip` e o
// da instrucao seguinte a ela.
.balign 8
.global programa_excecao_passo_na_chamada_inicio
programa_excecao_passo_na_chamada_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_pch, .Lcodigo_pch, .Lfim_codigo_pch
.Lcodigo_pch:
    mov     eax, 2
    pushfq
    or      qword ptr [rsp], 0x100
    popfq
    syscall
.Ldepois_pch:
    nop
    SOBREVIVEU .Lprender_pch
.Lfim_codigo_pch:
.global programa_excecao_passo_na_chamada_fim
programa_excecao_passo_na_chamada_fim:

// O `NT` ligado, e chamadas: `ceder` varias vezes -- cada uma passa o nucleo
// a outro fio pela troca voluntaria --, `id`, e a troca de imagem pelo
// `filho`. O `NT` nao faz nada no modo longo alem de dar #GP a um `iretq`:
// sem ele no `SFMask`, o kernel rodaria a chamada com ele ligado, e o fio que
// a troca voluntaria acordasse no meio de um tratador -- um que o tique
// preemptou -- daria #GP no `iretq` da volta, no anel 0. Com ele, o `filho`
// roda e sai com o codigo dele; sem a troca, sai com 66. O manifesto declara
// o `process.run`, o que a troca de imagem exerce -- como o do `exemplo`.
.balign 8
.global programa_excecao_nt_inicio
programa_excecao_nt_inicio:
.Lelf_nt:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   .Lcodigo_nt - .Lelf_nt   // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   .Lfim_codigo_nt - .Lcodigo_nt  // p_filesz
    .quad   .Lfim_codigo_nt - .Lcodigo_nt  // p_memsz
    .quad   4096                     // p_align

    // o manifesto: uma nota, que nao se carrega
    .long   4                        // PT_NOTE
    .long   4                        // PF_R
    .quad   .Lnota_nt - .Lelf_nt     // p_offset
    .quad   0                        // p_vaddr: nao se carrega
    .quad   0                        // p_paddr
    .quad   .Lfim_nota_nt - .Lnota_nt  // p_filesz
    .quad   .Lfim_nota_nt - .Lnota_nt  // p_memsz
    .quad   4                        // p_align
.Lcodigo_nt:
    pushfq
    or      qword ptr [rsp], 0x4000
    popfq
    mov     r12d, 16
.Lvolta_nt:
    mov     eax, 3
    syscall
    dec     r12d
    jnz     .Lvolta_nt
    mov     eax, 2
    syscall
    // executar("filho")
    lea     rdi, [rip + .Lnome_nt]
    mov     esi, 5
    mov     eax, 5
    syscall
    SOBREVIVEU .Lprender_nt
.Lnome_nt:
    .ascii  "filho"
.Lfim_codigo_nt:

.balign 4
.Lnota_nt:
    .long   5                        // tamanho do dono
    .long   .Lfim_texto_nt - .Ltexto_nt  // tamanho do conteudo
    .long   1                        // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_nt:
    .ascii  "duke-manifesto 1\nnome excecao-nt\npermite process.run\n"
.Lfim_texto_nt:
    .balign 4
.Lfim_nota_nt:
.global programa_excecao_nt_fim
programa_excecao_nt_fim:

// `int3`: o portao do #BP tem DPL 0, e o `int3` de um anel acima dele e um
// #GP com o vetor no codigo de erro -- 0x1A, o 3 com o bit da IDT.
.balign 8
.global programa_excecao_int3_inicio
programa_excecao_int3_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_int3, .Lcodigo_int3, .Lfim_codigo_int3
.Lcodigo_int3:
    int3
    SOBREVIVEU .Lprender_int3
.Lfim_codigo_int3:
.global programa_excecao_int3_fim
programa_excecao_int3_fim:

// O `push` com o `rsp` fora da forma canonica: a referencia a pilha num
// endereco nao canonico e #SS, com codigo zero.
.balign 8
.global programa_excecao_pilha_inicio
programa_excecao_pilha_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_pilha, .Lcodigo_pilha, .Lfim_codigo_pilha
.Lcodigo_pilha:
    movabs  rsp, 0x8000000000000008
.Lpush_pilha:
    push    rax
    SOBREVIVEU .Lprender_pilha
.Lfim_codigo_pilha:
.global programa_excecao_pilha_fim
programa_excecao_pilha_fim:

// --- o lote B3 do #448 ------------------------------------------------------

// O seletor 0x0F: o indice 1 do LDT (o TI ligado), com o RPL 3. O processador
// sai do reset -- e cada nucleo secundario, do INIT da partida -- com o LDTR
// valido, de base 0 e limite 0xFFFF: sem o LDT nulo, o `mov ds` leria o
// descritor no endereco 8 do processo, num acesso de supervisor, e a falha de
// pagina viria sem o U. Com o LDT nulo, o seletor e #GP com o codigo 0x0C.
.balign 8
.global programa_excecao_ldt_inicio
programa_excecao_ldt_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_ldt, .Lcodigo_ldt, .Lfim_codigo_ldt
.Lcodigo_ldt:
    mov     eax, 0x0F
.Lcarga_ldt:
    mov     ds, ax
    SOBREVIVEU .Lprender_ldt
.Lfim_codigo_ldt:
.global programa_excecao_ldt_fim
programa_excecao_ldt_fim:

// A mesma leitura do descritor, sem carregar segmento nenhum: o `lsl`, que o
// anel 3 executa. Com o LDT nulo, ele so apaga o ZF, e o processo sai com 55;
// sem ele, a mesma falha de pagina do supervisor no endereco 8.
.balign 8
.global programa_excecao_lsl_inicio
programa_excecao_lsl_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_lsl, .Lcodigo_lsl, .Lfim_codigo_lsl
.Lcodigo_lsl:
    mov     eax, 0x0F
    lsl     ecx, eax
    mov     eax, 0
    mov     edi, 55
    syscall
.Lprender_lsl:
    jmp     .Lprender_lsl
.Lfim_codigo_lsl:
.global programa_excecao_lsl_fim
programa_excecao_lsl_fim:

// O SIMD do anel 3, e o canal que ele seria: le o `xmm0` que o processo
// anterior deixou neste nucleo, deixa nele uma marca, e sai com 1 se a marca
// ja estava la -- com 0, se nao. Com o `CR0.TS` ligado, a primeira instrucao
// e #NM, e o processo morre dela. Os bytes por extenso: o alvo soft-float nao
// monta o `movq` dos registradores de SIMD.
.balign 8
.global programa_excecao_simd_inicio
programa_excecao_simd_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_simd, .Lcodigo_simd, .Lfim_codigo_simd
.Lcodigo_simd:
    .byte   0x66, 0x48, 0x0F, 0x7E, 0xC0      // movq rax, xmm0
    movabs  rcx, 0x5EC4E7D0D0E5A1A1
    .byte   0x66, 0x48, 0x0F, 0x6E, 0xC1      // movq xmm0, rcx
    xor     edi, edi
    cmp     rax, rcx
    sete    dil
    mov     eax, 0
    syscall
.Lprender_simd:
    jmp     .Lprender_simd
.Lfim_codigo_simd:
.global programa_excecao_simd_fim
programa_excecao_simd_fim:

// O x87 do anel 3: o `fld1`. Com o `CR0.TS` ligado, e #NM.
.balign 8
.global programa_excecao_x87_inicio
programa_excecao_x87_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_x87, .Lcodigo_x87, .Lfim_codigo_x87
.Lcodigo_x87:
    .byte   0xD9, 0xE8                        // fld1
    SOBREVIVEU .Lprender_x87
.Lfim_codigo_x87:
.global programa_excecao_x87_fim
programa_excecao_x87_fim:

// O passo adiado por um `mov ss` -- o cenario do CVE-2018-8897. O `TF` ligado,
// e o `mov ss` adia o #DB do passo ate depois da instrucao seguinte, a
// `syscall`: num processador, o #DB chega no anel 0, na primeira instrucao da
// entrada, ja na pilha da IST; o kernel apaga o `TF` do quadro e volta, a
// chamada `id` roda, e o processo morre do passo no anel 3, na volta, depois
// da `syscall`. O QEMU do TCG nao adia o passo: o #DB sai no anel 3 logo
// depois do `mov ss`, com o `rip` na `syscall`.
.balign 8
.global programa_excecao_movss_inicio
programa_excecao_movss_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_movss, .Lcodigo_movss, .Lfim_codigo_movss
.Lcodigo_movss:
    mov     eax, 2
    mov     dx, ss
    pushfq
    or      qword ptr [rsp], 0x100
    popfq
    mov     ss, dx
.Lna_syscall_movss:
    syscall
.Ldepois_movss:
    nop
    SOBREVIVEU .Lprender_movss
.Lfim_codigo_movss:
.global programa_excecao_movss_fim
programa_excecao_movss_fim:

// O seletor 0x1B: o descritor 3 da GDT, a base do `sysret`, que ninguem
// carrega -- de dados do usuario, e nao de codigo. O caso o marca ausente:
// o `mov ds` e #NP, com o seletor no codigo.
.balign 8
.global programa_excecao_ausente_inicio
programa_excecao_ausente_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_aus, .Lcodigo_aus, .Lfim_codigo_aus
.Lcodigo_aus:
    mov     eax, 0x1B
.Lcarga_aus:
    mov     ds, ax
    SOBREVIVEU .Lprender_aus
.Lfim_codigo_aus:
.global programa_excecao_ausente_fim
programa_excecao_ausente_fim:

// O mesmo seletor no `SS`: #SS, com o seletor no codigo.
.balign 8
.global programa_excecao_pilha_ausente_inicio
programa_excecao_pilha_ausente_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_paus, .Lcodigo_paus, .Lfim_codigo_paus
.Lcodigo_paus:
    mov     eax, 0x1B
.Lcarga_paus:
    mov     ss, ax
    SOBREVIVEU .Lprender_paus
.Lfim_codigo_paus:
.global programa_excecao_pilha_ausente_fim
programa_excecao_pilha_ausente_fim:

// `sysenter`: num Intel, ele existe no modo de 64 bits e entraria no anel 0
// pelo `IA32_SYSENTER_CS`; com ele em zero, e #GP(0). Num AMD -- e no QEMU do
// TCG, com o modelo `qemu64` --, e #UD no modo longo.
.balign 8
.global programa_excecao_sysenter_inicio
programa_excecao_sysenter_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_sysenter, .Lcodigo_sysenter, .Lfim_codigo_sysenter
.Lcodigo_sysenter:
    .byte   0x0F, 0x34                        // sysenter
    SOBREVIVEU .Lprender_sysenter
.Lfim_codigo_sysenter:
.global programa_excecao_sysenter_fim
programa_excecao_sysenter_fim:

// --- o lote B4 do #448 ------------------------------------------------------
//
// Nenhum programa daqui carrega o seletor do descritor 3 (0x18 a 0x1B): os
// casos do #NP e do #SS o marcam ausente, e um fio com ele guardado faria #NP
// no anel 0 na troca de contexto, que recarrega os seletores de cada fio.
//
// As marcas dos quatro seletores sao distintas, num programa e entre o
// receptor e o emissor do par: um seletor que a troca de contexto pusesse no
// lugar de outro -- o DS no FS, o FS no DS -- nao passa por certo (o achado 3
// do adversario do lote B4). Sao os descritores 4 (os dados do usuario) e 5
// (o codigo do usuario, que e legivel), os dois de DPL 3, com o RPL 3 e com o
// 1: 0x23, 0x2B, 0x21 e 0x29. O anel 3 carrega os quatro -- o RPL 1 nao passa
// do DPL --, o anel 0 tambem, e o retorno ao anel 3 nao os anula. Nenhum e
// o nulo, nem o nulo com um RPL (0x01 a 0x03), que o processador trata como
// o nulo.

// O FS, e o canal que ele seria: le o FS que o processo anterior deixou neste
// nucleo, deixa nele a marca -- 0x2B, o codigo do usuario, que e legivel -- e
// sai com 1 se a marca ja estava la; com 0, se nao. O kernel guarda os
// seletores de dados por fio, e um fio novo os recebe nulos: as duas rodadas
// no mesmo nucleo saem com zero.
.balign 8
.global programa_excecao_canal_fs_inicio
programa_excecao_canal_fs_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_cfs, .Lcodigo_cfs, .Lfim_codigo_cfs
.Lcodigo_cfs:
    mov     eax, fs
    xor     edi, edi
    cmp     eax, 0x2B
    sete    dil
    mov     ecx, 0x2B
    mov     fs, ecx
    mov     eax, 0
    syscall
.Lprender_cfs:
    jmp     .Lprender_cfs
.Lfim_codigo_cfs:
.global programa_excecao_canal_fs_fim
programa_excecao_canal_fs_fim:

// Os quatro, cada um com a sua marca -- 0x2B no DS, 0x23 no ES, 0x29 no FS e
// 0x21 no GS --: sai com 1 se os quatro ja estavam com ela.
.balign 8
.global programa_excecao_canal_seletores_inicio
programa_excecao_canal_seletores_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_csel, .Lcodigo_csel, .Lfim_codigo_csel
.Lcodigo_csel:
    xor     edi, edi
    mov     eax, ds
    cmp     eax, 0x2B
    jne     .Lmarcar_csel
    mov     eax, es
    cmp     eax, 0x23
    jne     .Lmarcar_csel
    mov     eax, fs
    cmp     eax, 0x29
    jne     .Lmarcar_csel
    mov     eax, gs
    cmp     eax, 0x21
    jne     .Lmarcar_csel
    mov     edi, 1
.Lmarcar_csel:
    mov     ecx, 0x2B
    mov     ds, ecx
    mov     ecx, 0x23
    mov     es, ecx
    mov     ecx, 0x29
    mov     fs, ecx
    mov     ecx, 0x21
    mov     gs, ecx
    mov     eax, 0
    syscall
.Lprender_csel:
    jmp     .Lprender_csel
.Lfim_codigo_csel:
.global programa_excecao_canal_seletores_fim
programa_excecao_canal_seletores_fim:

// O par: o receptor deixa as quatro marcas e cede 64 vezes, conferindo-as a
// cada volta; o emissor, preso ao mesmo nucleo e entrado no anel 3 junto com
// ele, deixa as outras -- 0x21 no DS, 0x29 no ES, 0x23 no FS e 0x2B no GS,
// cada uma diferente da do receptor no mesmo registrador -- e cede.
// Se uma marca do receptor mudou, ele morre do `ud2`: a falha contada e a
// prova, qualquer que seja a ordem das duas saidas. Guardados por fio,
// nenhuma falha; zerados a cada troca, o receptor morre tambem -- perdeu os
// dele.
.balign 8
.global programa_excecao_seletores_receptor_inicio
programa_excecao_seletores_receptor_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_srec, .Lcodigo_srec, .Lfim_codigo_srec
.Lcodigo_srec:
    mov     ecx, 0x2B
    mov     ds, ecx
    mov     ecx, 0x23
    mov     es, ecx
    mov     ecx, 0x29
    mov     fs, ecx
    mov     ecx, 0x21
    mov     gs, ecx
    mov     r12d, 64
.Lvolta_srec:
    mov     eax, 3                  // ceder
    syscall
    mov     eax, ds
    cmp     eax, 0x2B
    jne     .Lmudou_srec
    mov     eax, fs
    cmp     eax, 0x29
    jne     .Lmudou_srec
    mov     eax, es
    cmp     eax, 0x23
    jne     .Lmudou_srec
    mov     eax, gs
    cmp     eax, 0x21
    jne     .Lmudou_srec
    dec     r12d
    jnz     .Lvolta_srec
    xor     edi, edi
    mov     eax, 0
    syscall
.Lmudou_srec:
    ud2
.Lfim_codigo_srec:
.global programa_excecao_seletores_receptor_fim
programa_excecao_seletores_receptor_fim:

.balign 8
.global programa_excecao_seletores_emissor_inicio
programa_excecao_seletores_emissor_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_semi, .Lcodigo_semi, .Lfim_codigo_semi
.Lcodigo_semi:
    mov     r12d, 64
.Lvolta_semi:
    mov     ecx, 0x21
    mov     ds, ecx
    mov     ecx, 0x29
    mov     es, ecx
    mov     ecx, 0x23
    mov     fs, ecx
    mov     ecx, 0x2B
    mov     gs, ecx
    mov     eax, 3                  // ceder
    syscall
    dec     r12d
    jnz     .Lvolta_semi
    xor     edi, edi
    mov     eax, 0
    syscall
.Lprender_semi:
    jmp     .Lprender_semi
.Lfim_codigo_semi:
.global programa_excecao_seletores_emissor_fim
programa_excecao_seletores_emissor_fim:

// Os registradores na primeira entrada: os gerais -- menos o `rsp`, a pilha
// que o carregador deu -- e os quatro seletores de dados, todos em zero, como
// na troca de imagem: o processo novo nao recebe o que o kernel deixou neles.
// Sai com 1 se algum veio diferente de zero.
.balign 8
.global programa_excecao_registradores_inicio
programa_excecao_registradores_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_regs, .Lcodigo_regs, .Lfim_codigo_regs
.Lcodigo_regs:
    or      rax, rbx
    or      rax, rcx
    or      rax, rdx
    or      rax, rsi
    or      rax, rdi
    or      rax, rbp
    or      rax, r8
    or      rax, r9
    or      rax, r10
    or      rax, r11
    or      rax, r12
    or      rax, r13
    or      rax, r14
    or      rax, r15
    mov     ecx, ds
    or      rax, rcx
    mov     ecx, es
    or      rax, rcx
    mov     ecx, fs
    or      rax, rcx
    mov     ecx, gs
    or      rax, rcx
    xor     edi, edi
    test    rax, rax
    setnz   dil
    mov     eax, 0
    syscall
.Lprender_regs:
    jmp     .Lprender_regs
.Lfim_codigo_regs:
.global programa_excecao_registradores_fim
programa_excecao_registradores_fim:

// O UMIP: o `str`, o `sldt`, o `smsw`, o `sgdt` e o `sidt` do anel 3 sao
// #GP(0). Sem ele, dizem ao processo o seletor do TSS do nucleo, o do LDT, o
// CR0 baixo e onde estao a GDT e a IDT do kernel. Um programa por instrucao,
// ela na entrada; se seguir, sai com 66. O `sgdt` e o `sidt` escreveriam
// abaixo da pilha, na pagina dela.
.balign 8
.global programa_excecao_str_inicio
programa_excecao_str_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_str, .Lcodigo_str, .Lfim_codigo_str
.Lcodigo_str:
    str     ax
    SOBREVIVEU .Lprender_str
.Lfim_codigo_str:
.global programa_excecao_str_fim
programa_excecao_str_fim:

.balign 8
.global programa_excecao_sldt_inicio
programa_excecao_sldt_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_sldt, .Lcodigo_sldt, .Lfim_codigo_sldt
.Lcodigo_sldt:
    sldt    ax
    SOBREVIVEU .Lprender_sldt
.Lfim_codigo_sldt:
.global programa_excecao_sldt_fim
programa_excecao_sldt_fim:

.balign 8
.global programa_excecao_smsw_inicio
programa_excecao_smsw_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_smsw, .Lcodigo_smsw, .Lfim_codigo_smsw
.Lcodigo_smsw:
    smsw    eax
    SOBREVIVEU .Lprender_smsw
.Lfim_codigo_smsw:
.global programa_excecao_smsw_fim
programa_excecao_smsw_fim:

.balign 8
.global programa_excecao_sgdt_inicio
programa_excecao_sgdt_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_sgdt, .Lcodigo_sgdt, .Lfim_codigo_sgdt
.Lcodigo_sgdt:
    sgdt    [rsp - 16]
    SOBREVIVEU .Lprender_sgdt
.Lfim_codigo_sgdt:
.global programa_excecao_sgdt_fim
programa_excecao_sgdt_fim:

.balign 8
.global programa_excecao_sidt_inicio
programa_excecao_sidt_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_sidt, .Lcodigo_sidt, .Lfim_codigo_sidt
.Lcodigo_sidt:
    sidt    [rsp - 16]
    SOBREVIVEU .Lprender_sidt
.Lfim_codigo_sidt:
.global programa_excecao_sidt_fim
programa_excecao_sidt_fim:

// O `fwait` do anel 3: com o CR0.MP e o CR0.TS ligados, e #NM, como o x87.
// Sem o MP, ele so conferiria as excecoes do x87 pendentes -- nenhuma -- e o
// processo seguiria. O byte por extenso, como o `fld1`.
.balign 8
.global programa_excecao_fwait_inicio
programa_excecao_fwait_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_fwait, .Lcodigo_fwait, .Lfim_codigo_fwait
.Lcodigo_fwait:
    .byte   0x9B                              // fwait
    SOBREVIVEU .Lprender_fwait
.Lfim_codigo_fwait:
.global programa_excecao_fwait_fim
programa_excecao_fwait_fim:

// A heranca: o processo deixa as quatro marcas e bifurca. O filho confere que
// as recebeu do pai -- sai com 26 se nao -- e troca de imagem pelo `filho`,
// que confere que chegam nulas -- sai com 25 se nao, com o 24 de sempre se
// sim. O pai espera o filho, com o slot na pilha, e sai com o codigo dele. O
// manifesto declara o `process.run`, o que a troca de imagem exerce -- como o
// do `NT`.
.balign 8
.global programa_excecao_heranca_inicio
programa_excecao_heranca_inicio:
.Lelf_her:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   .Lcodigo_her - .Lelf_her // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   .Lfim_codigo_her - .Lcodigo_her  // p_filesz
    .quad   .Lfim_codigo_her - .Lcodigo_her  // p_memsz
    .quad   4096                     // p_align

    // o manifesto: uma nota, que nao se carrega
    .long   4                        // PT_NOTE
    .long   4                        // PF_R
    .quad   .Lnota_her - .Lelf_her   // p_offset
    .quad   0                        // p_vaddr: nao se carrega
    .quad   0                        // p_paddr
    .quad   .Lfim_nota_her - .Lnota_her  // p_filesz
    .quad   .Lfim_nota_her - .Lnota_her  // p_memsz
    .quad   4                        // p_align
.Lcodigo_her:
    mov     ecx, 0x2B
    mov     ds, ecx
    mov     ecx, 0x23
    mov     es, ecx
    mov     ecx, 0x29
    mov     fs, ecx
    mov     ecx, 0x21
    mov     gs, ecx
    mov     eax, 4                  // bifurcar
    syscall
    test    rax, rax
    jnz     .Lpai_her
    // O filho: os do pai, na hora do `fork`.
    mov     eax, ds
    cmp     eax, 0x2B
    jne     .Lsem_heranca
    mov     eax, fs
    cmp     eax, 0x29
    jne     .Lsem_heranca
    mov     eax, es
    cmp     eax, 0x23
    jne     .Lsem_heranca
    mov     eax, gs
    cmp     eax, 0x21
    jne     .Lsem_heranca
    // executar("filho"): a imagem nova os recebe nulos, e o `filho` confere.
    lea     rdi, [rip + .Lnome_her]
    mov     esi, 5
    mov     eax, 5
    syscall
    SOBREVIVEU .Lprender_filho_her
.Lsem_heranca:
    mov     edi, 26
    mov     eax, 0
    syscall
    jmp     .Lprender_her
.Lpai_her:
    // esperar(0, &slot), o slot na pilha, envenenado; e sair com o codigo do
    // filho.
    sub     rsp, 16
    mov     qword ptr [rsp], 100
    xor     edi, edi
    mov     rsi, rsp
    mov     eax, 9
    syscall
    mov     rdi, [rsp]
    mov     eax, 0
    syscall
.Lprender_her:
    jmp     .Lprender_her
.Lnome_her:
    .ascii  "filho"
.Lfim_codigo_her:

.balign 4
.Lnota_her:
    .long   5                        // tamanho do dono
    .long   .Lfim_texto_her - .Ltexto_her  // tamanho do conteudo
    .long   1                        // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_her:
    .ascii  "duke-manifesto 1\nnome excecao-heranca\npermite process.run\n"
.Lfim_texto_her:
    .balign 4
.Lfim_nota_her:
.global programa_excecao_heranca_fim
programa_excecao_heranca_fim:

// A troca de imagem com as flags ligadas: o `DF` -- com ele, o `memset` e o
// `memcpy` de um programa andam para tras -- e o `CF`, e o `executar` pelo
// `filho`, que confere as flags de um processo novo antes de qualquer
// instrucao que as mude, e sai com 25 se vieram desta imagem (o achado 1 do
// adversario do lote B4). Nem o `lea` nem o `mov` mudam as flags. Se a troca
// nao acontecer, sai com 66. O manifesto declara o `process.run`, como o do
// `NT`.
.balign 8
.global programa_excecao_troca_com_flags_inicio
programa_excecao_troca_com_flags_inicio:
.Lelf_tfl:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0x3E                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   .Lcodigo_tfl - .Lelf_tfl // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   .Lfim_codigo_tfl - .Lcodigo_tfl  // p_filesz
    .quad   .Lfim_codigo_tfl - .Lcodigo_tfl  // p_memsz
    .quad   4096                     // p_align

    // o manifesto: uma nota, que nao se carrega
    .long   4                        // PT_NOTE
    .long   4                        // PF_R
    .quad   .Lnota_tfl - .Lelf_tfl   // p_offset
    .quad   0                        // p_vaddr: nao se carrega
    .quad   0                        // p_paddr
    .quad   .Lfim_nota_tfl - .Lnota_tfl  // p_filesz
    .quad   .Lfim_nota_tfl - .Lnota_tfl  // p_memsz
    .quad   4                        // p_align
.Lcodigo_tfl:
    std
    stc
    lea     rdi, [rip + .Lnome_tfl]
    mov     esi, 5
    mov     eax, 5                  // executar("filho")
    syscall
    SOBREVIVEU .Lprender_tfl
.Lnome_tfl:
    .ascii  "filho"
.Lfim_codigo_tfl:

.balign 4
.Lnota_tfl:
    .long   5                        // tamanho do dono
    .long   .Lfim_texto_tfl - .Ltexto_tfl  // tamanho do conteudo
    .long   1                        // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_tfl:
    .ascii  "duke-manifesto 1\nnome excecao-troca-com-flags\npermite process.run\n"
.Lfim_texto_tfl:
    .balign 4
.Lfim_nota_tfl:
.global programa_excecao_troca_com_flags_fim
programa_excecao_troca_com_flags_fim:
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
    .short  3                 // e_phnum
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

    // o manifesto: uma nota, que nao se carrega — o kernel a le da imagem
    .long   4                                   // PT_NOTE
    .long   4                                   // PF_R
    .quad   .Lnota_ex - .Lelf_ex              // p_offset
    .quad   0                                   // p_vaddr: nao se carrega
    .quad   0                                   // p_paddr
    .quad   .Lfim_nota_ex - .Lnota_ex         // p_filesz
    .quad   .Lfim_nota_ex - .Lnota_ex         // p_memsz
    .quad   4                                   // p_align

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

// O manifesto, no formato de `protocolo::usuario::manifesto`: o que este
// programa exerce, e nada mais.
.balign 4
.Lnota_ex:
    .long   5                                   // tamanho do dono
    .long   .Lfim_texto_ex - .Ltexto_ex       // tamanho do conteudo
    .long   1                                   // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_ex:
    .ascii  "duke-manifesto 1\nnome exemplo\npermite process.run\n"
.Lfim_texto_ex:
    .balign 4
.Lfim_nota_ex:

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
    //
    // A troca de imagem entrega o NZCV em zero, o do `entrar`, e o TPIDR_EL0
    // zerado: o programa que entra nao tem direito ao estado do que saiu (o
    // lote B4 do #448). Se algum veio com o da imagem anterior, sai com 25,
    // antes da escrita que os casos da troca de imagem procuram. O `mrs` nao
    // muda as flags.
    mrs     x1, nzcv
    cbnz    x1, .Lsujo_fi
    mrs     x1, tpidr_el0
    cbnz    x1, .Lsujo_fi
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
.Lsujo_fi:
    mov     x8, #0
    mov     x0, #25
    svc     #0
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
    .short  3                        // e_phnum
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

    // o manifesto: uma nota, que nao se carrega — o kernel a le da imagem
    .long   4                                   // PT_NOTE
    .long   4                                   // PF_R
    .quad   .Lnota_le - .Lelf_le              // p_offset
    .quad   0                                   // p_vaddr: nao se carrega
    .quad   0                                   // p_paddr
    .quad   .Lfim_nota_le - .Lnota_le         // p_filesz
    .quad   .Lfim_nota_le - .Lnota_le         // p_memsz
    .quad   4                                   // p_align

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

// O manifesto, no formato de `protocolo::usuario::manifesto`: o que este
// programa exerce, e nada mais.
.balign 4
.Lnota_le:
    .long   5                                   // tamanho do dono
    .long   .Lfim_texto_le - .Ltexto_le       // tamanho do conteudo
    .long   1                                   // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_le:
    .ascii  "duke-manifesto 1\nnome leitor\npermite fs.read\n"
.Lfim_texto_le:
    .balign 4
.Lfim_nota_le:

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

// --- o contador: le o contador do timer generico no EL0 ---------------------
//
// A primeira instrucao, na entrada, le o `CNTVCT_EL0`. Com o `CNTKCTL_EL1`
// sem o `EL0VCTEN`, a leitura no EL0 e uma excecao sincrona para o EL1, e o
// processo morre ali.
.balign 8
.global programa_contador_inicio
programa_contador_inicio:

.Lelf_cont:
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
    .quad   .Lcodigo_cont - .Lelf_cont // p_offset
    .quad   VADDR_CODIGO                         // p_vaddr
    .quad   VADDR_CODIGO                         // p_paddr
    .quad   .Lfim_codigo_cont - .Lcodigo_cont  // p_filesz
    .quad   .Lfim_codigo_cont - .Lcodigo_cont  // p_memsz
    .quad   4096                                 // p_align

.Lcodigo_cont:
    mrs     x1, cntvct_el0

    // Inalcancavel: com o contador fora do EL0, a leitura acima e uma
    // excecao sincrona. Se chegarmos aqui, ela passou.
    mov     x8, #0
    mov     x0, #77
    svc     #0
.Lprender_cont:
    b       .Lprender_cont
.Lfim_codigo_cont:

.global programa_contador_fim
programa_contador_fim:

// --- o paciente: bifurca, espera o filho e sai com o codigo dele -----------
//
// Dois segmentos: o codigo, e oito bytes gravaveis onde `esperar` deposita o
// codigo de saida do filho. O slot comeca envenenado -- se ninguem escrever
// nele, o pai sai com o veneno mais um, que nao se confunde com nada.
.set OFF_CODIGO_PACIENTE, 32
.set VADDR_SLOT_PA,       VADDR_DADOS
.set VADDR_VALEU_PA,      VADDR_DADOS + 8
.set DADOS_PA,            16

.balign 8
.global programa_paciente_inicio
programa_paciente_inicio:

.Lelf_pa:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_PACIENTE   // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // codigo: leitura e execucao
    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_pa - .Lelf_pa              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_pa - .Lcodigo_pa       // p_filesz
    .quad   .Lfim_codigo_pa - .Lcodigo_pa       // p_memsz
    .quad   4096                                // p_align

    // dados: leitura e escrita, o slot do codigo de saida
    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_pa - .Lelf_pa               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_PA                            // p_filesz
    .quad   DADOS_PA                            // p_memsz
    .quad   4096                                // p_align

.Lcodigo_pa:
    .space  OFF_CODIGO_PACIENTE
    // bifurcar()
    mov     x8, #4
    svc     #0
    cbz     x0, .Lfilho_pa

    // O pai guarda o id do filho em x19, que o quadro da chamada preserva.
    mov     x19, x0

    // Um ponteiro invalido tem de ser recusado **sem** custar o filho: o
    // endereco 1 esta fora da faixa do usuario. Se a colheita acontecesse
    // antes da conferencia, esta chamada consumiria o filho e a seguinte
    // nao acharia mais ninguem.
    mov     x0, xzr
    mov     x1, #1
    mov     x8, #9
    svc     #0
    tbz     x0, #63, .Lfalhou_pa

    // esperar(0, &slot)
    mov     x0, xzr
    movz    x1, #(VADDR_SLOT_PA & 0xFFFF)
    movk    x1, #((VADDR_SLOT_PA >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_SLOT_PA >> 32) & 0xFFFF), lsl #32
    mov     x8, #9
    svc     #0

    // 1. o id colhido tem de ser o do filho
    cmp     x0, x19
    b.ne    .Lfalhou_pa

    // 2. a segunda espera tem de ser recusada: o filho ja foi colhido.
    //    `tbz` sobre o bit 63 pega qualquer valor nao-negativo.
    mov     x0, xzr
    mov     x1, xzr
    mov     x8, #9
    svc     #0
    tbz     x0, #63, .Lfalhou_pa

    // 3. o desfecho tem de dizer que o filho saiu por `sair`. Sem isto, um
    //    kernel que escrevesse zero para quem foi morto passaria batido:
    //    zero e um codigo de saida perfeitamente legitimo.
    movz    x2, #(VADDR_VALEU_PA & 0xFFFF)
    movk    x2, #((VADDR_VALEU_PA >> 16) & 0xFFFF), lsl #16
    movk    x2, #((VADDR_VALEU_PA >> 32) & 0xFFFF), lsl #32
    ldr     x0, [x2]
    cmp     x0, #1
    b.ne    .Lfalhou_pa

    // 4. sair com o codigo do filho mais um
    movz    x2, #(VADDR_SLOT_PA & 0xFFFF)
    movk    x2, #((VADDR_SLOT_PA >> 16) & 0xFFFF), lsl #16
    movk    x2, #((VADDR_SLOT_PA >> 32) & 0xFFFF), lsl #32
    ldr     x0, [x2]
    add     x0, x0, #1
    mov     x8, #0
    svc     #0

.Lfilho_pa:
    mov     x8, #0
    mov     x0, #51
    svc     #0

.Lfalhou_pa:
    mov     x8, #0
    mov     x0, #9
    svc     #0
.Lprender_pa:
    b       .Lprender_pa
.Lfim_codigo_pa:

.Ldados_pa:
    .quad   100                      // o veneno do codigo
    .quad   -1                       // o veneno do "vale?"
.Lfim_dados_pa:

.global programa_paciente_fim
programa_paciente_fim:

// --- o orfao: o filho morre de falha, e o pai precisa saber disso ---------
//
// Mesma forma do paciente, com uma diferenca no filho: em vez de sair, ele
// le a memoria do kernel e e morto. O que se afirma e do lado do pai -- que
// o desfecho diga `MORTO`, e nao um codigo de saida inventado.
.set OFF_CODIGO_ORFAO, 32
.set VADDR_SLOT_OR,    VADDR_DADOS
.set VADDR_VALEU_OR,   VADDR_DADOS + 8
.set DADOS_OR,         16

.balign 8
.global programa_orfao_inicio
programa_orfao_inicio:

.Lelf_or:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO + OFF_CODIGO_ORFAO      // e_entry
    .quad   64                       // e_phoff
    .quad   0                        // e_shoff
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    .long   1                                   // PT_LOAD
    .long   5                                   // PF_R | PF_X
    .quad   .Lcodigo_or - .Lelf_or              // p_offset
    .quad   VADDR_CODIGO                        // p_vaddr
    .quad   VADDR_CODIGO                        // p_paddr
    .quad   .Lfim_codigo_or - .Lcodigo_or       // p_filesz
    .quad   .Lfim_codigo_or - .Lcodigo_or       // p_memsz
    .quad   4096                                // p_align

    .long   1                                   // PT_LOAD
    .long   6                                   // PF_R | PF_W
    .quad   .Ldados_or - .Lelf_or               // p_offset
    .quad   VADDR_DADOS                         // p_vaddr
    .quad   VADDR_DADOS                         // p_paddr
    .quad   DADOS_OR                            // p_filesz
    .quad   DADOS_OR                            // p_memsz
    .quad   4096                                // p_align

.Lcodigo_or:
    .space  OFF_CODIGO_ORFAO
    // bifurcar()
    mov     x8, #4
    svc     #0
    cbz     x0, .Lfilho_or

    // esperar(0, &slot)
    mov     x0, xzr
    movz    x1, #(VADDR_SLOT_OR & 0xFFFF)
    movk    x1, #((VADDR_SLOT_OR >> 16) & 0xFFFF), lsl #16
    movk    x1, #((VADDR_SLOT_OR >> 32) & 0xFFFF), lsl #32
    mov     x8, #9
    svc     #0
    tbnz    x0, #63, .Lfalhou_or

    // O desfecho tem de dizer MORTO (0). Este e o ponto do programa: um
    // kernel que escrevesse "saiu com 0" para quem foi morto reprovaria
    // aqui, e em nenhum outro lugar.
    movz    x2, #(VADDR_VALEU_OR & 0xFFFF)
    movk    x2, #((VADDR_VALEU_OR >> 16) & 0xFFFF), lsl #16
    movk    x2, #((VADDR_VALEU_OR >> 32) & 0xFFFF), lsl #32
    ldr     x0, [x2]
    cbnz    x0, .Lfalhou_or

    mov     x8, #0
    mov     x0, #53
    svc     #0

.Lfilho_or:
    // Le o comeco da imagem do kernel, em 0x4008_0000. E uma falha de
    // protecao, e o filho morre sem nunca chamar `sair`.
    movz    x0, #0x4008, lsl #16
    ldr     x0, [x0]
    // Inalcancavel.
    mov     x8, #0
    mov     x0, #10
    svc     #0

.Lfalhou_or:
    mov     x8, #0
    mov     x0, #10
    svc     #0
.Lprender_or:
    b       .Lprender_or
.Lfim_codigo_or:

.Ldados_or:
    .quad   100                      // o veneno do codigo
    .quad   -1                       // o veneno do "vale?"
.Lfim_dados_or:

.global programa_orfao_fim
programa_orfao_fim:

// --- as excecoes do EL0: um programa por `brk` -----------------------------
//
// O lote B2 do #448. O `brk` do EL0 mata o processo, como as outras falhas do
// EL0; os dois imediatos do estouro de proposito -- 0xE5 e 0xE6, os do
// `debug.trigger` -- so valem do EL1. Cada programa tem o `brk` na entrada;
// se seguir, sai com 66, que a suite reconhece como "a excecao nao matou".
.macro ELF_DE_UM_SEGMENTO elf, codigo, fim
\elf:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  1                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   \codigo - \elf           // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   \fim - \codigo           // p_filesz
    .quad   \fim - \codigo           // p_memsz
    .quad   4096                     // p_align
.endm

// A saida de quem sobreviveu ao `brk`: sair(66), e o laco que nao volta.
.macro SOBREVIVEU rotulo
    mov     x8, #0
    mov     x0, #66
    svc     #0
\rotulo:
    b       \rotulo
.endm

// `brk #0xe5`: o imediato do estouro de proposito da pilha de excecao.
.balign 8
.global programa_excecao_brk_estouro_inicio
programa_excecao_brk_estouro_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_brke5, .Lcodigo_brke5, .Lfim_codigo_brke5
.Lcodigo_brke5:
    brk     #0xe5
    SOBREVIVEU .Lprender_brke5
.Lfim_codigo_brke5:
.global programa_excecao_brk_estouro_fim
programa_excecao_brk_estouro_fim:

// `brk #0xe6`: o do estouro na borda da guarda.
.balign 8
.global programa_excecao_brk_borda_inicio
programa_excecao_brk_borda_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_brke6, .Lcodigo_brke6, .Lfim_codigo_brke6
.Lcodigo_brke6:
    brk     #0xe6
    SOBREVIVEU .Lprender_brke6
.Lfim_codigo_brke6:
.global programa_excecao_brk_borda_fim
programa_excecao_brk_borda_fim:

// `brk #0`: um ponto de parada qualquer.
.balign 8
.global programa_excecao_brk_inicio
programa_excecao_brk_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_brk0, .Lcodigo_brk0, .Lfim_codigo_brk0
.Lcodigo_brk0:
    brk     #0
    SOBREVIVEU .Lprender_brk0
.Lfim_codigo_brk0:
.global programa_excecao_brk_fim
programa_excecao_brk_fim:

// --- o lote B3 do #448 ------------------------------------------------------

// O FP/SIMD do EL0, e o canal que ele seria: le o `d0` que o processo
// anterior deixou neste nucleo, deixa nele uma marca, e sai com 1 se a marca
// ja estava la -- com 0, se nao. Com o `CPACR_EL1.FPEN` em 00, a primeira
// instrucao e a excecao da classe 0x07, e o processo morre dela. `.inst`: o
// alvo -softfloat nao monta o `fmov`.
.balign 8
.global programa_excecao_simd_inicio
programa_excecao_simd_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_simd, .Lcodigo_simd, .Lfim_codigo_simd
.Lcodigo_simd:
    .inst   0x9E660000              // fmov x0, d0
    movz    x1, #0xA1A1
    movk    x1, #0xD0E5, lsl #16
    movk    x1, #0xE7D0, lsl #32
    movk    x1, #0x5EC4, lsl #48
    .inst   0x9E670020              // fmov d0, x1
    cmp     x0, x1
    cset    x0, eq
    mov     x8, #0
    svc     #0
.Lprender_simd:
    b       .Lprender_simd
.Lfim_codigo_simd:
.global programa_excecao_simd_fim
programa_excecao_simd_fim:

// O `msr daif` do EL0, com o I ligado: com o `SCTLR_EL1.UMA` desligado, e a
// excecao da classe 0x18, e o processo morre dela; ligado, o processo
// mascararia as IRQs do nucleo, e nenhum tique o tiraria dali.
.balign 8
.global programa_excecao_daif_inicio
programa_excecao_daif_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_daif, .Lcodigo_daif, .Lfim_codigo_daif
.Lcodigo_daif:
    mov     x0, #0x80
.Lmsr_daif:
    msr     daif, x0
    SOBREVIVEU .Lprender_daif
.Lfim_codigo_daif:
.global programa_excecao_daif_fim
programa_excecao_daif_fim:

// O `wfi` do EL0: com o `SCTLR_EL1.nTWI` desligado, e a excecao da classe
// 0x01, e o processo morre dela. A arquitetura so prende o `wfi` que iria
// dormir: com uma IRQ ja pendente, ele passa, a IRQ e atendida, e o laco o
// repete -- quatro vezes, e o processo sai pelo SOBREVIVEU, se nenhum foi
// preso.
.balign 8
.global programa_excecao_wfi_inicio
programa_excecao_wfi_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_wfi, .Lcodigo_wfi, .Lfim_codigo_wfi
.Lcodigo_wfi:
    mov     x2, #4
.Lwfi:
    wfi
    subs    x2, x2, #1
    b.ne    .Lwfi
    SOBREVIVEU .Lprender_wfi
.Lfim_codigo_wfi:
.global programa_excecao_wfi_fim
programa_excecao_wfi_fim:

// --- o lote B4 do #448 ------------------------------------------------------

// O TPIDR_EL0, e o canal que ele seria: o EL0 o escreve e o le sem armadilha
// que o EL1 possa ligar. Le o que o processo anterior deixou neste nucleo,
// deixa nele a marca e sai com 1 se a marca ja estava la; com 0, se nao. O
// kernel o guarda por fio, e um fio novo o recebe zerado: as duas rodadas no
// mesmo nucleo saem com zero.
.balign 8
.global programa_excecao_canal_tpidr_inicio
programa_excecao_canal_tpidr_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_ctp, .Lcodigo_ctp, .Lfim_codigo_ctp
.Lcodigo_ctp:
    mrs     x0, tpidr_el0
    movz    x1, #0xA1A1
    movk    x1, #0xD0E5, lsl #16
    movk    x1, #0xE7D0, lsl #32
    movk    x1, #0x5EC4, lsl #48
    msr     tpidr_el0, x1
    cmp     x0, x1
    cset    x0, eq
    mov     x8, #0
    svc     #0
.Lprender_ctp:
    b       .Lprender_ctp
.Lfim_codigo_ctp:
.global programa_excecao_canal_tpidr_fim
programa_excecao_canal_tpidr_fim:

// O par: o receptor deixa a marca e cede 64 vezes, conferindo-a a cada volta;
// o emissor, preso ao mesmo nucleo e entrado no EL0 junto com ele, escreve
// outra e cede. Se a marca do receptor mudou, ele morre do `brk #1`: a falha
// contada e a prova, qualquer que seja a ordem das duas saidas. Guardado por
// fio, nenhuma falha; zerado a cada troca, o receptor morre tambem -- perdeu
// o dele.
.balign 8
.global programa_excecao_tpidr_receptor_inicio
programa_excecao_tpidr_receptor_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_trec, .Lcodigo_trec, .Lfim_codigo_trec
.Lcodigo_trec:
    movz    x19, #0x1111
    movk    x19, #0x2222, lsl #16
    movk    x19, #0x3333, lsl #32
    movk    x19, #0x4444, lsl #48
    msr     tpidr_el0, x19
    mov     x20, #64
.Lvolta_trec:
    mov     x8, #3                  // ceder
    svc     #0
    mrs     x0, tpidr_el0
    cmp     x0, x19
    b.ne    .Lmudou_trec
    subs    x20, x20, #1
    b.ne    .Lvolta_trec
    mov     x0, #0
    mov     x8, #0
    svc     #0
.Lmudou_trec:
    brk     #1
.Lfim_codigo_trec:
.global programa_excecao_tpidr_receptor_fim
programa_excecao_tpidr_receptor_fim:

.balign 8
.global programa_excecao_tpidr_emissor_inicio
programa_excecao_tpidr_emissor_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_temi, .Lcodigo_temi, .Lfim_codigo_temi
.Lcodigo_temi:
    movz    x19, #0xDEAD
    mov     x20, #64
.Lvolta_temi:
    msr     tpidr_el0, x19
    mov     x8, #3                  // ceder
    svc     #0
    subs    x20, x20, #1
    b.ne    .Lvolta_temi
    mov     x0, #0
    mov     x8, #0
    svc     #0
.Lprender_temi:
    b       .Lprender_temi
.Lfim_codigo_temi:
.global programa_excecao_tpidr_emissor_fim
programa_excecao_tpidr_emissor_fim:

// Os registradores na primeira entrada: o x0 a o x30, o TPIDR_EL0 e o
// TPIDRRO_EL0, todos em zero -- o `sp` e a pilha que o carregador deu. Sai
// com 1 se algum veio diferente de zero.
.balign 8
.global programa_excecao_registradores_inicio
programa_excecao_registradores_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_rega, .Lcodigo_rega, .Lfim_codigo_rega
.Lcodigo_rega:
    orr     x0, x0, x1
    orr     x0, x0, x2
    orr     x0, x0, x3
    orr     x0, x0, x4
    orr     x0, x0, x5
    orr     x0, x0, x6
    orr     x0, x0, x7
    orr     x0, x0, x8
    orr     x0, x0, x9
    orr     x0, x0, x10
    orr     x0, x0, x11
    orr     x0, x0, x12
    orr     x0, x0, x13
    orr     x0, x0, x14
    orr     x0, x0, x15
    orr     x0, x0, x16
    orr     x0, x0, x17
    orr     x0, x0, x18
    orr     x0, x0, x19
    orr     x0, x0, x20
    orr     x0, x0, x21
    orr     x0, x0, x22
    orr     x0, x0, x23
    orr     x0, x0, x24
    orr     x0, x0, x25
    orr     x0, x0, x26
    orr     x0, x0, x27
    orr     x0, x0, x28
    orr     x0, x0, x29
    orr     x0, x0, x30
    mrs     x1, tpidr_el0
    orr     x0, x0, x1
    mrs     x1, tpidrro_el0
    orr     x0, x0, x1
    cmp     x0, #0
    cset    x0, ne
    mov     x8, #0
    svc     #0
.Lprender_rega:
    b       .Lprender_rega
.Lfim_codigo_rega:
.global programa_excecao_registradores_fim
programa_excecao_registradores_fim:

// O canal do depurador (o DCC): com o `MDSCR_EL1.TDCC` ligado, o EL0 que le o
// `MDCCSR_EL0` -- ou escreve o `DBGDTRTX_EL0` -- cai no EL1, a classe 0x18, e
// o processo morre dela. Desligado, o `TXfull` que um processo ligasse, o
// seguinte veria. Se seguir, sai com 66.
.balign 8
.global programa_excecao_mdccsr_inicio
programa_excecao_mdccsr_inicio:
    ELF_DE_UM_SEGMENTO .Lelf_dcc, .Lcodigo_dcc, .Lfim_codigo_dcc
.Lcodigo_dcc:
    mrs     x0, mdccsr_el0
    SOBREVIVEU .Lprender_dcc
.Lfim_codigo_dcc:
.global programa_excecao_mdccsr_fim
programa_excecao_mdccsr_fim:

// A heranca: o processo deixa a marca no TPIDR_EL0 e bifurca. O filho confere
// que a recebeu do pai -- sai com 26 se nao -- e troca de imagem pelo
// `filho`, que confere que chega zerado -- 25 se nao, o 24 de sempre se sim.
// O pai espera o filho, com o slot na pilha, e sai com o codigo dele. O
// manifesto declara o `process.run`.
.balign 8
.global programa_excecao_heranca_inicio
programa_excecao_heranca_inicio:
.Lelf_her:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   .Lcodigo_her - .Lelf_her // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   .Lfim_codigo_her - .Lcodigo_her  // p_filesz
    .quad   .Lfim_codigo_her - .Lcodigo_her  // p_memsz
    .quad   4096                     // p_align

    // o manifesto: uma nota, que nao se carrega
    .long   4                        // PT_NOTE
    .long   4                        // PF_R
    .quad   .Lnota_her - .Lelf_her   // p_offset
    .quad   0                        // p_vaddr: nao se carrega
    .quad   0                        // p_paddr
    .quad   .Lfim_nota_her - .Lnota_her  // p_filesz
    .quad   .Lfim_nota_her - .Lnota_her  // p_memsz
    .quad   4                        // p_align
.Lcodigo_her:
    movz    x19, #0x1111
    movk    x19, #0x2222, lsl #16
    movk    x19, #0x3333, lsl #32
    movk    x19, #0x4444, lsl #48
    msr     tpidr_el0, x19
    mov     x8, #4                  // bifurcar
    svc     #0
    cbnz    x0, .Lpai_her
    // O filho: o do pai, na hora do `fork`.
    mrs     x0, tpidr_el0
    cmp     x0, x19
    b.ne    .Lsem_heranca
    // executar("filho"): a imagem nova o recebe zerado, e o `filho` confere.
    adr     x0, .Lnome_her
    mov     x1, #5
    mov     x8, #5
    svc     #0
    SOBREVIVEU .Lprender_filho_her
.Lsem_heranca:
    mov     x0, #26
    mov     x8, #0
    svc     #0
    b       .Lprender_her
.Lpai_her:
    // esperar(0, &slot), o slot na pilha, envenenado; e sair com o codigo do
    // filho.
    sub     sp, sp, #16
    mov     x2, #100
    str     x2, [sp]
    mov     x0, xzr
    mov     x1, sp
    mov     x8, #9
    svc     #0
    ldr     x0, [sp]
    mov     x8, #0
    svc     #0
.Lprender_her:
    b       .Lprender_her
.Lnome_her:
    .ascii  "filho"
.Lfim_codigo_her:

.balign 4
.Lnota_her:
    .long   5                        // tamanho do dono
    .long   .Lfim_texto_her - .Ltexto_her  // tamanho do conteudo
    .long   1                        // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_her:
    .ascii  "duke-manifesto 1\nnome excecao-heranca\npermite process.run\n"
.Lfim_texto_her:
    .balign 4
.Lfim_nota_her:
.global programa_excecao_heranca_fim
programa_excecao_heranca_fim:

// A troca de imagem com as flags ligadas: o N, o Z, o C e o V, e o
// `executar` pelo `filho`, que confere o NZCV de um processo novo -- zero --
// antes de qualquer instrucao que o mude, e sai com 25 se veio desta imagem
// (o achado 1 do adversario do lote B4). Nem o `adr` nem o `mov` mudam as
// flags. Se a troca nao acontecer, sai com 66. O manifesto declara o
// `process.run`.
.balign 8
.global programa_excecao_troca_com_flags_inicio
programa_excecao_troca_com_flags_inicio:
.Lelf_tfl:
    .byte   0x7F, 0x45, 0x4C, 0x46   // \x7fELF
    .byte   2, 1, 1, 0               // 64 bits, little-endian, versao 1
    .byte   0, 0, 0, 0, 0, 0, 0, 0   // resto do e_ident
    .short  2                        // e_type: ET_EXEC
    .short  0xB7                     // e_machine
    .long   1                        // e_version
    .quad   VADDR_CODIGO             // e_entry
    .quad   64                       // e_phoff: a tabela vem logo apos
    .quad   0                        // e_shoff: sem secoes
    .long   0                        // e_flags
    .short  64                       // e_ehsize
    .short  56                       // e_phentsize
    .short  2                        // e_phnum
    .short  0                        // e_shentsize
    .short  0                        // e_shnum
    .short  0                        // e_shstrndx

    // segmento de codigo: leitura e execucao, nunca escrita
    .long   1                        // PT_LOAD
    .long   5                        // PF_R | PF_X
    .quad   .Lcodigo_tfl - .Lelf_tfl // p_offset
    .quad   VADDR_CODIGO             // p_vaddr
    .quad   VADDR_CODIGO             // p_paddr
    .quad   .Lfim_codigo_tfl - .Lcodigo_tfl  // p_filesz
    .quad   .Lfim_codigo_tfl - .Lcodigo_tfl  // p_memsz
    .quad   4096                     // p_align

    // o manifesto: uma nota, que nao se carrega
    .long   4                        // PT_NOTE
    .long   4                        // PF_R
    .quad   .Lnota_tfl - .Lelf_tfl   // p_offset
    .quad   0                        // p_vaddr: nao se carrega
    .quad   0                        // p_paddr
    .quad   .Lfim_nota_tfl - .Lnota_tfl  // p_filesz
    .quad   .Lfim_nota_tfl - .Lnota_tfl  // p_memsz
    .quad   4                        // p_align
.Lcodigo_tfl:
    movz    x0, #0xF000, lsl #16
    msr     nzcv, x0                 // N, Z, C e V ligados
    adr     x0, .Lnome_tfl
    mov     x1, #5
    mov     x8, #5                  // executar("filho")
    svc     #0
    SOBREVIVEU .Lprender_tfl
.Lnome_tfl:
    .ascii  "filho"
.Lfim_codigo_tfl:

.balign 4
.Lnota_tfl:
    .long   5                        // tamanho do dono
    .long   .Lfim_texto_tfl - .Ltexto_tfl  // tamanho do conteudo
    .long   1                        // o tipo do manifesto
    .ascii  "Duke\0"
    .balign 4
.Ltexto_tfl:
    .ascii  "duke-manifesto 1\nnome excecao-troca-com-flags\npermite process.run\n"
.Lfim_texto_tfl:
    .balign 4
.Lfim_nota_tfl:
.global programa_excecao_troca_com_flags_fim
programa_excecao_troca_com_flags_fim:
"#
);
