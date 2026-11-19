//! Os casos `excecoes:` — a exceção que um processo provoca mata o processo,
//! e não a máquina (o lote B2 do #448). Uma exceção vinda do anel sem
//! privilégio é culpa do processo, e não do kernel: o post-mortem pararia a
//! máquina para todos os titulares, e o que estava no anel da auditoria e
//! ainda não tinha ido ao journal ficaria só no cadáver — um processo agiria
//! e apagaria o fim da própria trilha.
//!
//! Um programa mínimo por caso, montado à mão em `usuario::exemplo` (ver
//! `exemplo::Excecao`), com a exceção na entrada ou depois do mínimo que ela
//! pede. Em cada núcleo ligado, o processo roda num fio do kernel preso ao
//! núcleo, que entra no anel sem privilégio pelo `usuario::programa::executar`
//! — o caminho do `contador` —, e o caso confere:
//!
//! - a falha contada (`traps`), com o nome, o `pc` e o código dela;
//! - a linha `processo morto por ...` no log, uma vez;
//! - o processo fora da tabela — o coletor o recolheu;
//! - e o núcleo seguindo: um fio novo preso a ele roda. A suíte segue com
//!   a máquina.
//!
//! Se o processo seguisse depois da exceção, sairia com
//! `exemplo::CODIGO_DA_EXCECAO`; se a exceção fosse fatal, a suíte acabaria
//! aqui.
//!
//! No x86: o `ud2` (`#UD`), a divisão por zero (`#DE`), o `int1` (`#DB`), o
//! `TF` ligado seguido de um `nop` e de uma `syscall` (`#DB` no anel 3), o
//! `int3` (o `#GP` do portão de DPL 0), o `push` com o `rsp` não canônico
//! (`#SS`), e o `NT` ligado seguido de chamadas — `ceder`, `id` e a troca de
//! imagem —, que não é exceção nenhuma: o processo troca de imagem e sai com
//! o código do `filho`. No ARM: o `brk` com os dois imediatos do estouro de
//! propósito e com outro qualquer.
//!
//! Dois desses o emulador não reproduz como o processador: o `int1` é um
//! `#UD` no QEMU do TCG (8.2), e o `push` não canônico, uma falha de página
//! no endereço truncado no 8.2 e um `#GP` com o código zero no QEMU da CI. O
//! caso aceita as formas, a do processador e as dos emuladores, e diz qual é
//! qual; o `#DB` do anel 3 no emulador é o dos casos do passo.
//! As outras exceções com código de erro — `#TS`, `#AC`, `#CP`, `#VC`,
//! `#SX` — e o `#OF`, o `#BR`, o `#VE` e o `#HV` não se alcançam do anel 3
//! no emulador, com o que o kernel liga: os tratadores delas usam a mesma
//! regra (`arch::x86_64::idt`), que o `#NP` e o `#SS` do descritor ausente,
//! o `#GP` e a falha de página exercitam aqui e no `contador`. O `#MF` e o
//! `#XM` não se alcançam mais: o x87 e o SSE do anel 3 são `#NM` antes (o
//! `CR0.TS`, desde o lote B3).
//!
//! O lote B3 do #448 acrescentou, pelo que o adversário do lote B2 achou, no
//! x86: o seletor do LDT (`mov ds` com 0x0F), que o LDT nulo recusa com
//! `#GP`, e o `lsl` dele, que não falha; a falha de página de um acesso do
//! supervisor pedido pelo anel 3 — o LDT de teste, com a base sem página —,
//! que a culpa pelo `CS` dá ao processo; o SSE e o x87, que o `CR0.TS` põe
//! no `#NM` — o SSE duas vezes por núcleo, pelo canal que a segunda rodada
//! diria —; o passo no anel 0 que o próprio kernel liga, e que volta sem o
//! `TF`, e o passo adiado pelo `mov ss`; o `#NP` e o `#SS` do descritor
//! ausente, o grupo com código de erro alcançado do anel 3; e o `sysenter`.
//! No ARM: o FP/SIMD, que o `CPACR_EL1` em zero põe na classe 0x07, também
//! duas vezes por núcleo; o `msr daif`, que o `SCTLR_EL1.UMA` desligado
//! recusa; e o `wfi`, que o `nTWI` desligado prende. E, nas duas, o regime de cada núcleo — o que o kernel escreve em
//! vez de herdar do firmware —, e, no x86, a pilha da IST do `#MC`.
//!
//! O lote B4 do #448 acrescentou, pelo que o adversário do lote B3 achou, o
//! estado por fio que passava de um processo ao seguinte no mesmo núcleo —
//! o `TPIDR_EL0` no ARM, os seletores `DS`, `ES`, `FS` e `GS` no x86 —: o
//! canal, duas rodadas por núcleo; o par, um receptor e um emissor presos ao
//! mesmo núcleo e entrados juntos, que cedem um ao outro — e reprova o
//! kernel que só zera o registrador a cada troca —; e a herança, o `fork`
//! que passa o do pai ao filho e a troca de imagem que o zera, conferida
//! pelo próprio `filho`. Nas duas, os registradores da primeira entrada,
//! zerados. No x86, o `str`, o `sldt`, o `smsw`, o `sgdt` e o `sidt` do
//! anel 3, que o UMIP põe no `#GP(0)`, e o `fwait`, que o `CR0.MP` põe no
//! `#NM`. No ARM, o canal do depurador do EL0, que o `MDSCR_EL1.TDCC`
//! prende. E o regime de cada núcleo conferido bit a bit — no x86, contra o
//! CPUID, com o `XCR0` e os `DR0` a `DR3`; no ARM, com o `MDSCR_EL1` e o
//! `TPIDRRO_EL0`.
//!
//! E, pelo que o adversário do próprio lote achou: a troca de imagem com as
//! flags ligadas — o `DF` e o `CF` no x86, o `NZCV` no ARM —, em que o
//! `filho` confere que são as de um processo novo; o regime sujo conferido
//! inteiro, item por item, com o `SEP`, o `xsave`, o `RDTSCP` e o `RDPID` do
//! x86 pelo CPUID, e as bases do `FS` e do `GS` e o `IA32_TSC_AUX` no x86; e
//! o par, que confere também que os dois se revezaram.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

use super::{Resultado, esperar_ate, nucleos_secundarios};
use crate::usuario::exemplo::{self, Excecao};

/// Os núcleos ligados: o primeiro e os secundários.
fn nucleos() -> alloc::vec::Vec<usize> {
    let mut nucleos = alloc::vec![0];
    nucleos.extend(nucleos_secundarios());
    nucleos
}

/// O que a morte de um processo pela exceção deixa.
struct Esperada {
    /// O nome da falha, como a contabilidade (`traps`) o guarda.
    nome: &'static str,
    /// O motivo, como o log o diz: `processo morto por <motivo> #N em pc=P`
    /// — e, na falha de página, `, endereco E` depois.
    motivo: &'static str,
    /// Onde a exceção deixa o `rip`/`elr`, a partir da entrada.
    deslocamento: u64,
    /// O código da falha confere?
    codigo: fn(u64) -> bool,
    /// O endereço acusado, quando a falha tem um que o caso confere.
    endereco: Option<u64>,
}

/// As formas aceitas da morte de um processo: a do processador e, quando o
/// emulador não a reproduz, a do emulador — dita no caso.
type Formas = &'static [Esperada];

/// O núcleo em que o último hospedeiro rodou, ou `u64::MAX`.
static RODOU: AtomicU64 = AtomicU64::new(u64::MAX);

/// Os programas, pelo número que o hospedeiro recebe.
const PROGRAMAS: &[Excecao] = &[
    #[cfg(target_arch = "x86_64")]
    Excecao::Ud2,
    #[cfg(target_arch = "x86_64")]
    Excecao::Divisao,
    #[cfg(target_arch = "x86_64")]
    Excecao::Int1,
    #[cfg(target_arch = "x86_64")]
    Excecao::Passo,
    #[cfg(target_arch = "x86_64")]
    Excecao::PassoNaChamada,
    #[cfg(target_arch = "x86_64")]
    Excecao::Nt,
    #[cfg(target_arch = "x86_64")]
    Excecao::Int3,
    #[cfg(target_arch = "x86_64")]
    Excecao::Pilha,
    #[cfg(target_arch = "x86_64")]
    Excecao::Ldt,
    #[cfg(target_arch = "x86_64")]
    Excecao::Lsl,
    #[cfg(target_arch = "x86_64")]
    Excecao::Simd,
    #[cfg(target_arch = "x86_64")]
    Excecao::X87,
    #[cfg(target_arch = "x86_64")]
    Excecao::MovSs,
    #[cfg(target_arch = "x86_64")]
    Excecao::Ausente,
    #[cfg(target_arch = "x86_64")]
    Excecao::PilhaAusente,
    #[cfg(target_arch = "x86_64")]
    Excecao::Sysenter,
    #[cfg(target_arch = "aarch64")]
    Excecao::BrkDoEstouro,
    #[cfg(target_arch = "aarch64")]
    Excecao::BrkDaBorda,
    #[cfg(target_arch = "aarch64")]
    Excecao::Brk,
    #[cfg(target_arch = "aarch64")]
    Excecao::Simd,
    #[cfg(target_arch = "aarch64")]
    Excecao::Daif,
    #[cfg(target_arch = "aarch64")]
    Excecao::Wfi,
    #[cfg(target_arch = "x86_64")]
    Excecao::CanalFs,
    #[cfg(target_arch = "x86_64")]
    Excecao::CanalSeletores,
    #[cfg(target_arch = "x86_64")]
    Excecao::SeletoresReceptor,
    #[cfg(target_arch = "x86_64")]
    Excecao::SeletoresEmissor,
    #[cfg(target_arch = "x86_64")]
    Excecao::Str,
    #[cfg(target_arch = "x86_64")]
    Excecao::Sldt,
    #[cfg(target_arch = "x86_64")]
    Excecao::Smsw,
    #[cfg(target_arch = "x86_64")]
    Excecao::Sgdt,
    #[cfg(target_arch = "x86_64")]
    Excecao::Sidt,
    #[cfg(target_arch = "x86_64")]
    Excecao::Fwait,
    #[cfg(target_arch = "aarch64")]
    Excecao::CanalTpidr,
    #[cfg(target_arch = "aarch64")]
    Excecao::TpidrReceptor,
    #[cfg(target_arch = "aarch64")]
    Excecao::TpidrEmissor,
    #[cfg(target_arch = "aarch64")]
    Excecao::Mdccsr,
    Excecao::Registradores,
    Excecao::Heranca,
    Excecao::TrocaComFlags,
];

/// O hospedeiro: anota o núcleo e entra no anel sem privilégio com o
/// programa da vez. Não volta: o processo morre da exceção, ou sai.
extern "C" fn hospedar(indice: u64) -> ! {
    RODOU.store(crate::arch::nucleo_atual() as u64, SeqCst);
    // O caso da culpa pelo `CS` entra com o LDT de teste neste núcleo — ver
    // [`excecoes_a_falha_de_pagina_do_supervisor_pelo_anel_3_mata_o_processo`].
    // O fio está preso ao núcleo: o `LDTR` carregado aqui é o do núcleo em
    // que o processo vai rodar.
    #[cfg(target_arch = "x86_64")]
    if COM_O_LDT_DE_TESTE.load(SeqCst) {
        crate::arch::atual::gdt::carregar_o_ldt_de_teste();
    }
    let imagem = exemplo::bytes_da_excecao(PROGRAMAS[indice as usize]);
    match crate::usuario::programa::executar(imagem) {
        Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
        Err(falha) => {
            crate::log_error!(
                "teste",
                "nao foi possivel entrar em userspace: {}",
                falha.motivo()
            );
            crate::fios::terminar()
        }
    }
}

/// A entrada do ELF — o `e_entry`.
fn entrada_de(imagem: &[u8]) -> Result<u64, &'static str> {
    imagem
        .get(24..32)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or("a imagem do programa da excecao nao tem a entrada")
}

/// O processo do programa `e` roda num fio preso ao núcleo `cpu`; devolve o
/// id do fio quando ele acabou — pela falha, ou pela saída.
fn rodar(e: Excecao, cpu: usize) -> Result<u64, &'static str> {
    let indice = PROGRAMAS
        .iter()
        .position(|&p| p == e)
        .ok_or("o programa da excecao nao esta na tabela do caso")?;
    RODOU.store(u64::MAX, SeqCst);
    let falhas = crate::traps::total();
    let id = crate::fios::criar_no_nucleo("teste-excecao", hospedar, indice as u64, cpu)?.numero();
    esperar_ate(
        || {
            !crate::fios::vivo(id)
                && (crate::traps::total() > falhas || crate::usuario::ultima_saida().is_some())
        },
        600,
    )
    .map_err(|_| "o processo da excecao nao caiu nem saiu")?;
    if RODOU.load(SeqCst) != cpu as u64 {
        return Err("o processo da excecao nao rodou no nucleo dele");
    }
    Ok(id)
}

/// O processo `id` saiu da tabela — o coletor o recolheu —, e o núcleo
/// `cpu` segue: um fio novo preso a ele roda.
fn fora_da_tabela_e_o_nucleo_segue(id: u64, cpu: usize) -> Resultado {
    esperar_ate(|| !crate::fios::na_tabela_de_teste(id), 600)
        .map_err(|_| "o processo morto pela excecao nao saiu da tabela")?;
    SEGUIU.store(u64::MAX, SeqCst);
    crate::fios::criar_no_nucleo("teste-excecao-segue", marcar, 0, cpu)?;
    esperar_ate(|| SEGUIU.load(SeqCst) == cpu as u64, 300)
        .map_err(|_| "o nucleo nao rodou um fio novo depois da excecao")
}

/// O núcleo em que o último fio de [`fora_da_tabela_e_o_nucleo_segue`]
/// rodou, ou `u64::MAX`.
static SEGUIU: AtomicU64 = AtomicU64::new(u64::MAX);

extern "C" fn marcar(_argumento: u64) -> ! {
    SEGUIU.store(crate::arch::nucleo_atual() as u64, SeqCst);
    crate::fios::terminar()
}

/// As linhas do log, desde `desde`, que dizem que um processo morreu como
/// `linha` diz: ela inteira, ou com o endereço acusado depois — o da falha
/// de página.
fn linhas_da_morte(desde: u64, linha: &str) -> usize {
    let mut n = 0;
    crate::log::ultimos(64, crate::log::Level::Trace, |r| {
        let m = r.mensagem();
        n += (r.seq >= desde
            && r.subsistema == "usuario"
            && m.strip_prefix(linha)
                .is_some_and(|resto| resto.is_empty() || resto.starts_with(", endereco ")))
            as usize;
    });
    n
}

/// O processo do programa `e` morre da exceção dele em cada núcleo ligado,
/// numa das `formas` — ver o cabeçalho do módulo.
fn morre_pela_excecao(e: Excecao, formas: Formas) -> Resultado {
    em_cada_nucleo(|cpu| morre_no_nucleo(e, formas, cpu))
}

/// Roda `f` em cada núcleo ligado, até o último, e devolve o primeiro erro:
/// um núcleo que reprova não esconde o que os outros fariam — o log diz o de
/// cada um. A máquina parada num deles, claro, para a rodada ali.
fn em_cada_nucleo(mut f: impl FnMut(usize) -> Resultado) -> Resultado {
    let mut primeiro = Ok(());
    for cpu in nucleos() {
        if let Err(motivo) = f(cpu) {
            crate::log_error!("teste", "excecoes: no nucleo {}: {}", cpu, motivo);
            if primeiro.is_ok() {
                primeiro = Err(motivo);
            }
        }
    }
    primeiro
}

/// O processo do programa `e` morre da exceção dele no núcleo `cpu`, numa
/// das `formas`: a falha contada, com o nome, o `pc`, o código e o endereço
/// dela; a linha do log uma vez; o processo fora da tabela; e o núcleo
/// seguindo. Se o processo sair, o código de saída fica em
/// `usuario::ultima_saida` para quem chamou.
fn morre_no_nucleo(e: Excecao, formas: Formas, cpu: usize) -> Resultado {
    let entrada = entrada_de(exemplo::bytes_da_excecao(e))?;
    crate::usuario::limpar_ultima_saida();
    let falhas = crate::traps::total();
    let desde = crate::log::total_emitidos();
    let id = rodar(e, cpu)?;
    if let Some(saida) = crate::usuario::ultima_saida() {
        crate::log_error!(
            "teste",
            "excecoes: no nucleo {}, o processo saiu com {}",
            cpu,
            saida
        );
        return Err(if saida == exemplo::CODIGO_DA_EXCECAO {
            "o processo seguiu depois da excecao"
        } else {
            "o processo saiu em vez de morrer da excecao"
        });
    }
    if crate::traps::total() <= falhas {
        return Err("a excecao do processo nao foi contada");
    }
    let falha = crate::traps::ultima().ok_or("a falha da excecao nao foi contada")?;
    crate::log_info!(
        "teste",
        "excecoes: no nucleo {}, {} em pc={:#x}, codigo {:#x}, endereco {:?}",
        cpu,
        falha.nome,
        falha.pc,
        falha.codigo,
        falha.endereco
    );
    let Some(esperada) = formas.iter().find(|f| {
        falha.nome == f.nome
            && falha.pc == entrada + f.deslocamento
            && (f.codigo)(falha.codigo)
            && f.endereco.is_none_or(|e| falha.endereco == Some(e))
    }) else {
        for f in formas {
            crate::log_error!(
                "teste",
                "esperada {} em pc={:#x}, endereco {:?}",
                f.nome,
                entrada + f.deslocamento,
                f.endereco
            );
        }
        return Err("a falha contada nao foi a da excecao do programa, na instrucao dela");
    };
    let linha = alloc::format!(
        "processo morto por {} #{} em pc={:#x}",
        esperada.motivo,
        falha.seq,
        entrada + esperada.deslocamento
    );
    if linhas_da_morte(desde, &linha) != 1 {
        crate::log_error!("teste", "esperada `{}`", linha);
        return Err("o log nao diz que o processo morreu pela excecao");
    }
    fora_da_tabela_e_o_nucleo_segue(id, cpu)
}

/// O processo do programa `e` não morre de exceção nenhuma em cada núcleo
/// ligado: sai com `codigo`, nenhuma falha é contada, e ele sai da tabela.
#[cfg(target_arch = "x86_64")]
fn sai_sem_falha(e: Excecao, codigo: i64) -> Resultado {
    em_cada_nucleo(|cpu| {
        crate::usuario::limpar_ultima_saida();
        let falhas = crate::traps::total();
        let id = rodar(e, cpu)?;
        let saida = crate::usuario::ultima_saida();
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o processo saiu com {:?}; {} falha(s)",
            cpu,
            saida,
            crate::traps::total() - falhas
        );
        if crate::traps::total() != falhas {
            if let Some(falha) = crate::traps::ultima() {
                crate::log_error!(
                    "teste",
                    "{} em pc={:#x}, codigo {:#x}, endereco {:?}",
                    falha.nome,
                    falha.pc,
                    falha.codigo,
                    falha.endereco
                );
            }
            return Err("uma falha foi contada para um processo que nao devia falhar");
        }
        if saida != Some(codigo) {
            return Err("o processo nao saiu com o codigo dele");
        }
        fora_da_tabela_e_o_nucleo_segue(id, cpu)
    })
}

/// O processo do programa do SIMD morre da exceção dele duas vezes seguidas
/// em cada núcleo ligado, numa das `formas`. A segunda rodada no mesmo
/// núcleo é a que diria o canal: sem a armadilha, a primeira sai com zero e
/// deixa a marca no registrador, e a segunda a lê e sai com
/// [`exemplo::CODIGO_DO_CANAL`]. As duas rodam sempre, e o log diz como
/// cada uma acabou: é a segunda que mostra o canal.
fn o_simd_morre_e_nao_passa_ao_seguinte(formas: Formas) -> Resultado {
    em_cada_nucleo(|cpu| {
        let primeira = morre_no_nucleo(Excecao::Simd, formas, cpu);
        let saida_da_primeira = crate::usuario::ultima_saida();
        let segunda = morre_no_nucleo(Excecao::Simd, formas, cpu);
        let saida_da_segunda = crate::usuario::ultima_saida();
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o SIMD: a primeira rodada {:?} (saida {:?}), a segunda {:?} \
             (saida {:?})",
            cpu,
            primeira,
            saida_da_primeira,
            segunda,
            saida_da_segunda
        );
        if saida_da_segunda == Some(exemplo::CODIGO_DO_CANAL) {
            return Err(
                "o canal: a segunda rodada no mesmo nucleo leu o registrador que a primeira deixou",
            );
        }
        primeira.and(segunda)
    })
}

/// O código zero, o dos `#SS` e `#GP` sem seletor.
#[cfg(target_arch = "x86_64")]
fn zero(codigo: u64) -> bool {
    codigo == 0
}

/// O `DR6` de um `#DB` do passo: o `BS`, o bit 14.
#[cfg(target_arch = "x86_64")]
fn do_passo(dr6: u64) -> bool {
    dr6 & (1 << 14) != 0
}

/// O `DR6` de um `#DB` que não é do passo: sem o `BS`.
#[cfg(target_arch = "x86_64")]
fn nao_do_passo(dr6: u64) -> bool {
    dr6 & (1 << 14) == 0
}

/// O `#GP` do `int3` contra o portão de DPL 0: o código diz o vetor 3, com
/// o bit da IDT — `(3 << 3) | 2`.
#[cfg(target_arch = "x86_64")]
fn do_portao_do_int3(codigo: u64) -> bool {
    codigo == (3 << 3) | 2
}

/// `ud2`: o processo morre de `#UD` na instrução da entrada.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_ud2_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Ud2,
        &[Esperada {
            nome: "invalid_opcode",
            motivo: "instrucao invalida",
            deslocamento: 0,
            codigo: zero,
            endereco: None,
        }],
    )
}

/// A divisão por zero: o processo morre de `#DE` na instrução da entrada.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_a_divisao_por_zero_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Divisao,
        &[Esperada {
            nome: "divide_error",
            motivo: "erro de divisao",
            deslocamento: 0,
            codigo: zero,
            endereco: None,
        }],
    )
}

/// O `int1`: o processo morre. Num processador, de `#DB` — o `icebp` não
/// confere o DPL do portão —, sem o passo no `DR6`, com o `rip` depois da
/// instrução; antes do lote B2, o `#DB` ausente levava ao `#NP`, ausente, e
/// ao `#DF`, fatal. O QEMU do TCG (8.2) não o implementa: é um `#UD` na
/// instrução, que também parava a máquina — a rodada antes da correção o
/// mostrou (`FALHA FATAL: invalid_opcode`). As duas formas valem; o `#DB`
/// do anel 3 no emulador é o dos casos do passo.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_int1_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Int1,
        &[
            Esperada {
                nome: "debug",
                motivo: "depuracao",
                deslocamento: exemplo::DEPOIS_DO_INT1,
                codigo: nao_do_passo,
                endereco: None,
            },
            Esperada {
                nome: "invalid_opcode",
                motivo: "instrucao invalida",
                deslocamento: 0,
                codigo: zero,
                endereco: None,
            },
        ],
    )
}

/// O `TF` ligado e um `nop`: o processo morre do `#DB` do passo, depois do
/// `nop`.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_passo_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Passo,
        &[Esperada {
            nome: "debug",
            motivo: "depuracao",
            deslocamento: exemplo::DEPOIS_DO_PASSO,
            codigo: do_passo,
            endereco: None,
        }],
    )
}

/// O `TF` ligado e a `syscall`: a chamada roda — o `SFMask` apaga o `TF` na
/// entrada do anel 0, e o `#DB` não chega ao kernel antes da troca de pilha
/// —, e o processo morre do `#DB` do passo no anel 3, na volta, com o `rip`
/// na instrução seguinte à `syscall`. A chamada contada é a prova de que ela
/// rodou.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_passo_na_chamada_mata_o_processo_no_anel_3() -> Resultado {
    let chamadas = crate::usuario::estatisticas().0;
    morre_pela_excecao(
        Excecao::PassoNaChamada,
        &[Esperada {
            nome: "debug",
            motivo: "depuracao",
            deslocamento: exemplo::DEPOIS_DO_PASSO_NA_CHAMADA,
            codigo: do_passo,
            endereco: None,
        }],
    )?;
    if crate::usuario::estatisticas().0 < chamadas + nucleos().len() as u64 {
        return Err("a chamada com o passo ligado nao rodou");
    }
    Ok(())
}

/// O `int3`: o portão do `#BP` tem DPL 0, e o `int3` do anel 3 é um `#GP`
/// com o vetor no código — o processo morre dele, e nada vai ao `#BP`, que
/// registraria e seguiria.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_int3_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Int3,
        &[Esperada {
            nome: "general_protection_fault",
            motivo: "falha de protecao",
            deslocamento: 0,
            codigo: do_portao_do_int3,
            endereco: None,
        }],
    )
}

/// O `push` com o `rsp` não canônico: o processo morre, no `push`. Num
/// processador, de `#SS` com o código zero — a referência à pilha num
/// endereço não canônico —, que antes do lote B2 ia pela entrada ausente ao
/// `#NP` e ao `#DF`, fatal. O QEMU do TCG (8.2) não confere a forma
/// canônica nesse acesso: a escrita vai ao endereço truncado, e é uma falha
/// de página no zero, com o código de uma escrita do anel 3 numa página
/// ausente — a rodada antes da correção o mostrou. O QEMU da CI confere a
/// forma canônica, mas dá `#GP` com o código zero, e não `#SS` — a CI 513 o
/// mostrou. As três formas valem: todas matam o processo no `push`, pela
/// mesma regra.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_a_pilha_nao_canonica_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Pilha,
        &[
            Esperada {
                nome: "stack_segment_fault",
                motivo: "falha de segmento de pilha",
                deslocamento: exemplo::PUSH_DA_PILHA,
                codigo: zero,
                endereco: None,
            },
            Esperada {
                nome: "page_fault",
                motivo: "falha de pagina",
                deslocamento: exemplo::PUSH_DA_PILHA,
                codigo: escrita_do_anel_3_sem_pagina,
                endereco: None,
            },
            Esperada {
                nome: "general_protection_fault",
                motivo: "falha de protecao",
                deslocamento: exemplo::PUSH_DA_PILHA,
                codigo: zero,
                endereco: None,
            },
        ],
    )
}

/// O código de uma falha de página de uma escrita do anel 3 numa página
/// ausente: o `W` e o `U`, sem o `P`.
#[cfg(target_arch = "x86_64")]
fn escrita_do_anel_3_sem_pagina(codigo: u64) -> bool {
    codigo & 0b111 == 0b110
}

/// O companheiro do caso do `NT` deve parar.
#[cfg(target_arch = "x86_64")]
static PARAR_O_COMPANHEIRO: AtomicBool = AtomicBool::new(false);
/// Quantas vezes o companheiro foi escolhido para rodar, como ele mesmo o
/// vê — mais um: zero é "ainda não rodou".
#[cfg(target_arch = "x86_64")]
static VOLTAS_DO_COMPANHEIRO: AtomicU64 = AtomicU64::new(0);

/// O companheiro: gira, sem ceder, no núcleo do processo do `NT` — só o
/// tique o tira da vez, e ele volta pela saída do tratador, pelo `iretq`.
#[cfg(target_arch = "x86_64")]
extern "C" fn companheiro(_argumento: u64) -> ! {
    while !PARAR_O_COMPANHEIRO.load(SeqCst) {
        VOLTAS_DO_COMPANHEIRO.store(crate::fios::escalonamentos_de_teste() + 1, SeqCst);
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    }
    crate::fios::terminar()
}

/// O `NT` ligado, e chamadas: o processo cede o núcleo várias vezes, pede o
/// `id` e troca de imagem pelo `filho`, que sai com o código dele. O `NT` só
/// faz uma coisa no modo longo: o `iretq` com ele ligado é `#GP`. Sem ele no
/// `SFMask`, o kernel rodaria a chamada com ele, e a troca voluntária do
/// `ceder` o passaria ao companheiro — um fio que só gira, preso ao mesmo
/// núcleo, e que o tique tirou da vez dentro do tratador dele: o `iretq` da
/// volta daria `#GP` no anel 0, e a máquina acabaria aqui. Nenhuma falha é
/// contada, o companheiro volta à vez, e o processo sai da tabela. E o `NT`
/// não chega à imagem nova: o `filho` confere as flags de um processo novo,
/// e sai com [`exemplo::CODIGO_DO_FILHO_SUJO`] se as recebeu da anterior (o
/// achado 1 do adversário do lote B4 do #448 — antes, ele rodava com o
/// `RFLAGS` 0x4246: o `NT`, o `IF`, o `ZF` e o `PF`).
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_nt_nas_chamadas_nao_chega_ao_kernel() -> Resultado {
    for cpu in nucleos() {
        PARAR_O_COMPANHEIRO.store(false, SeqCst);
        VOLTAS_DO_COMPANHEIRO.store(0, SeqCst);
        let companheiro =
            crate::fios::criar_no_nucleo("teste-excecao-companheiro", companheiro, 0, cpu)?
                .numero();
        let resultado = (|| -> Resultado {
            esperar_ate(|| VOLTAS_DO_COMPANHEIRO.load(SeqCst) != 0, 300)
                .map_err(|_| "o companheiro do caso do NT nao rodou")?;
            crate::usuario::limpar_ultima_saida();
            let falhas = crate::traps::total();
            let trocas = crate::usuario::estatisticas_de_processo().1;
            let voltas = VOLTAS_DO_COMPANHEIRO.load(SeqCst);
            let id = rodar(Excecao::Nt, cpu)?;
            let voltas = VOLTAS_DO_COMPANHEIRO.load(SeqCst).saturating_sub(voltas);
            crate::log_info!(
                "teste",
                "excecoes: no nucleo {}, o processo com o NT saiu com {:?}; o companheiro voltou \
                 {} vezes",
                cpu,
                crate::usuario::ultima_saida(),
                voltas
            );
            match crate::usuario::ultima_saida() {
                Some(exemplo::CODIGO_DO_FILHO) => {}
                Some(exemplo::CODIGO_DO_FILHO_SUJO) => {
                    return Err("a imagem nova recebeu as flags da que saiu, com o NT");
                }
                _ => return Err("o processo com o NT nao trocou de imagem e saiu pelo filho"),
            }
            if crate::usuario::estatisticas_de_processo().1 != trocas + 1 {
                return Err("o processo com o NT nao trocou de imagem exatamente uma vez");
            }
            if crate::traps::total() != falhas {
                return Err("uma falha foi contada no caso do NT");
            }
            if voltas == 0 {
                return Err("o companheiro nao voltou a vez enquanto o processo cedia");
            }
            fora_da_tabela_e_o_nucleo_segue(id, cpu)
        })();
        PARAR_O_COMPANHEIRO.store(true, SeqCst);
        esperar_ate(|| !crate::fios::vivo(companheiro), 300)
            .map_err(|_| "o companheiro do caso do NT nao parou")?;
        resultado?;
    }
    Ok(())
}

/// O `ESR_EL1` de um `brk` com o imediato `imediato`: a classe 0x3C.
#[cfg(target_arch = "aarch64")]
fn do_brk(codigo: u64, imediato: u64) -> bool {
    (codigo >> 26) & 0x3F == 0x3C && codigo & 0xFFFF == imediato
}

/// `brk #0xe5` do EL0 — o imediato do estouro de propósito, que só vale do
/// EL1: o processo morre do `brk`, e a pilha de exceção não afunda.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_brk_do_estouro_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::BrkDoEstouro,
        &[Esperada {
            nome: "breakpoint",
            motivo: "breakpoint",
            deslocamento: 0,
            codigo: |c| do_brk(c, 0xE5),
            endereco: None,
        }],
    )
}

/// `brk #0xe6` do EL0 — o do estouro na borda: o processo morre do `brk`, e
/// ninguém pisa no fundo da guarda.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_brk_da_borda_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::BrkDaBorda,
        &[Esperada {
            nome: "breakpoint",
            motivo: "breakpoint",
            deslocamento: 0,
            codigo: |c| do_brk(c, 0xE6),
            endereco: None,
        }],
    )
}

/// `brk #0` do EL0: o processo morre, e não registra e segue.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_brk_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Brk,
        &[Esperada {
            nome: "breakpoint",
            motivo: "breakpoint",
            deslocamento: 0,
            codigo: |c| do_brk(c, 0),
            endereco: None,
        }],
    )
}

// ---------------------------------------------------------------------------
// O lote B3 do #448: o LDT do reset, o FP/SIMD entre processos, o passo do
// `mov ss` e o segmento ausente
// ---------------------------------------------------------------------------

/// O código do `#GP` do seletor 0x0F: o índice 1 com o TI, sem o RPL.
#[cfg(target_arch = "x86_64")]
fn do_seletor_do_ldt(codigo: u64) -> bool {
    codigo == 0x0C
}

/// O código do `#NP` e do `#SS` do seletor 0x1B: o índice 3, sem o RPL.
#[cfg(target_arch = "x86_64")]
fn do_seletor_da_base_do_sysret(codigo: u64) -> bool {
    codigo == 0x18
}

/// O código de uma falha de página de uma leitura do supervisor numa
/// página ausente: sem o `P`, o `W` e o `U` — o acesso implícito que o
/// processador faz à tabela de descritores, ainda que a instrução seja do
/// anel 3.
#[cfg(target_arch = "x86_64")]
fn leitura_do_supervisor_sem_pagina(codigo: u64) -> bool {
    codigo & 0b111 == 0
}

/// O seletor do LDT carregado pelo processo — o `mov ds` com 0x0F, o índice
/// 1 com o TI —: com o LDT nulo que o kernel carrega em todo núcleo, o
/// processador recusa com `#GP`, o seletor no código (0x0C), e o processo
/// morre dele. O processador sai do reset — e cada núcleo secundário, do
/// INIT da partida — com o `LDTR` válido, de base 0 e limite 0xFFFF; antes do
/// LDT nulo, o `mov ds` lia o descritor no endereço 8 do processo, num
/// acesso de supervisor, e a falha de página sem o `U` era tomada por do
/// kernel: `FALHA FATAL page_fault` no endereço 8 (o achado 1 do adversário
/// do lote B2).
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_seletor_do_ldt_mata_o_processo_pelo_gp() -> Resultado {
    morre_pela_excecao(
        Excecao::Ldt,
        &[Esperada {
            nome: "general_protection_fault",
            motivo: "falha de protecao",
            deslocamento: exemplo::CARGA_DO_SELETOR,
            codigo: do_seletor_do_ldt,
            endereco: None,
        }],
    )
}

/// O `lsl` do seletor do LDT: a mesma leitura do descritor, sem carregar
/// segmento nenhum — o anel 3 o executa. Com o LDT nulo, ele só apaga o
/// `ZF`: nenhuma falha, e o processo sai com o código dele. Antes, a mesma
/// falha de página do supervisor no endereço 8, fatal.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_lsl_de_um_seletor_do_ldt_nao_falha() -> Resultado {
    sai_sem_falha(Excecao::Lsl, exemplo::CODIGO_DO_LSL)
}

/// O próximo hospedeiro carrega o LDT de teste no núcleo dele antes de
/// entrar — ver `gdt::carregar_o_ldt_de_teste`.
#[cfg(target_arch = "x86_64")]
static COM_O_LDT_DE_TESTE: AtomicBool = AtomicBool::new(false);

/// O núcleo em que o último fio de [`devolver_o_ldt_nulo`] rodou, ou
/// `u64::MAX`.
#[cfg(target_arch = "x86_64")]
static LDT_DEVOLVIDO: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(target_arch = "x86_64")]
extern "C" fn largar_o_ldt(_argumento: u64) -> ! {
    crate::arch::atual::gdt::largar_o_ldt_de_teste();
    LDT_DEVOLVIDO.store(crate::arch::nucleo_atual() as u64, SeqCst);
    crate::fios::terminar()
}

/// O núcleo `cpu` volta ao LDT nulo: um fio preso a ele o carrega.
#[cfg(target_arch = "x86_64")]
fn devolver_o_ldt_nulo(cpu: usize) -> Resultado {
    LDT_DEVOLVIDO.store(u64::MAX, SeqCst);
    crate::fios::criar_no_nucleo("teste-excecao-ldt", largar_o_ldt, 0, cpu)?;
    esperar_ate(|| LDT_DEVOLVIDO.load(SeqCst) == cpu as u64, 300)
        .map_err(|_| "o nucleo nao voltou ao LDT nulo")
}

/// A falha de página que uma instrução do anel 3 provoca num acesso do
/// **supervisor** — o código sem o `U` — é do processo: a culpa pelo `CS`
/// do quadro, como em toda exceção e como no Linux. O caso a provoca com o
/// LDT de teste no núcleo — a base num endereço sem página, como a do reset
/// —, e o `mov ds` com o seletor 0x0F: o processador lê o descritor em
/// `BASE_DO_LDT_DE_TESTE + 8`, num acesso de supervisor. Sem a culpa pelo
/// `CS`, só o `U` decidia, e a falha era do kernel: `FALHA FATAL page_fault`.
/// Depois, o núcleo volta ao LDT nulo.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_a_falha_de_pagina_do_supervisor_pelo_anel_3_mata_o_processo() -> Resultado {
    em_cada_nucleo(|cpu| {
        COM_O_LDT_DE_TESTE.store(true, SeqCst);
        let resultado = morre_no_nucleo(
            Excecao::Ldt,
            &[Esperada {
                nome: "page_fault",
                motivo: "falha de pagina",
                deslocamento: exemplo::CARGA_DO_SELETOR,
                codigo: leitura_do_supervisor_sem_pagina,
                endereco: Some(crate::arch::atual::gdt::BASE_DO_LDT_DE_TESTE + 8),
            }],
            cpu,
        );
        COM_O_LDT_DE_TESTE.store(false, SeqCst);
        devolver_o_ldt_nulo(cpu)?;
        resultado
    })
}

/// A morte pelo `#NM`: a unidade de ponto flutuante presa pelo `CR0.TS`, na
/// instrução da entrada.
#[cfg(target_arch = "x86_64")]
const PELO_NM: Formas = &[Esperada {
    nome: "device_not_available",
    motivo: "dispositivo indisponivel",
    deslocamento: 0,
    codigo: zero,
    endereco: None,
}];

/// O SSE do anel 3 — o `movq` do `xmm0` — cai no `#NM`, em cada núcleo,
/// duas vezes seguidas: o `CR0.TS` ligado em todo núcleo, e nunca desligado,
/// prende o ponto flutuante e o SIMD fora do anel 0, e o processo morre na
/// primeira instrução. Antes, o kernel não salvava nem zerava os
/// registradores de um processo para o outro, e o `xmm0` que um deixava
/// chegava ao seguinte no mesmo núcleo: a primeira rodada saía com zero, a
/// segunda com 1 — um canal entre titulares, por fora do gate (o achado 2
/// do adversário do lote B2).
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_sse_do_anel_3_cai_no_nm_e_nao_passa_ao_seguinte() -> Resultado {
    o_simd_morre_e_nao_passa_ao_seguinte(PELO_NM)
}

/// O x87 do anel 3 — o `fld1` — cai no `#NM`, em cada núcleo. Antes, ele
/// rodava, e o processo seguia.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_x87_do_anel_3_cai_no_nm() -> Resultado {
    morre_pela_excecao(Excecao::X87, PELO_NM)
}

/// O que cada núcleo viu do passo no anel 0: o `RFLAGS` depois, mais um —
/// zero é "ainda não viu" —, os passos do anel 0 contados no meio, e o
/// núcleo em que rodou.
#[cfg(target_arch = "x86_64")]
static FLAGS_DO_PASSO: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static PASSOS_NO_MEIO: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static ONDE_O_PASSO: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(target_arch = "x86_64")]
extern "C" fn dar_o_passo_no_anel_0(_argumento: u64) -> ! {
    let antes = crate::traps::passos_do_anel_0();
    let flags = crate::arch::atual::passo_no_anel_0_de_teste();
    PASSOS_NO_MEIO.store(crate::traps::passos_do_anel_0() - antes, SeqCst);
    ONDE_O_PASSO.store(crate::arch::nucleo_atual() as u64, SeqCst);
    FLAGS_DO_PASSO.store(flags.wrapping_add(1), SeqCst);
    crate::fios::terminar()
}

/// O passo no anel 0 volta: o próprio kernel liga o `TF` no anel 0, com as
/// interrupções mascaradas, e roda dois `nop` — o `#DB` do passo chega
/// depois do primeiro, com o `BS` no `DR6`, como o que o `mov ss` de um
/// processo adia até depois da `syscall` (o cenário do CVE-2018-8897). Em
/// cada núcleo: o tratador apaga o `TF` do quadro e volta — o `RFLAGS` lido
/// depois não tem o `TF` —, a conta dos passos do anel 0 anda um, e nenhuma
/// falha é contada. Sem o conserto, o `#DB` do anel 0 é fatal, e a suíte
/// acaba aqui.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_passo_no_anel_0_volta_sem_o_tf() -> Resultado {
    const TF: u64 = 1 << 8;
    em_cada_nucleo(|cpu| {
        FLAGS_DO_PASSO.store(0, SeqCst);
        ONDE_O_PASSO.store(u64::MAX, SeqCst);
        let falhas = crate::traps::total();
        crate::fios::criar_no_nucleo("teste-passo-no-anel-0", dar_o_passo_no_anel_0, 0, cpu)?;
        esperar_ate(|| FLAGS_DO_PASSO.load(SeqCst) != 0, 300)
            .map_err(|_| "o passo no anel 0 nao voltou")?;
        let flags = FLAGS_DO_PASSO.load(SeqCst).wrapping_sub(1);
        let passos = PASSOS_NO_MEIO.load(SeqCst);
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o passo no anel 0 voltou: rflags {:#x}, {} passo(s) contado(s)",
            cpu,
            flags,
            passos
        );
        if ONDE_O_PASSO.load(SeqCst) != cpu as u64 {
            return Err("o passo no anel 0 nao rodou no nucleo dele");
        }
        if flags & TF != 0 {
            return Err("o TF continuou ligado no anel 0 depois do passo");
        }
        if passos != 1 {
            return Err("a conta dos passos do anel 0 nao andou um");
        }
        if crate::traps::total() != falhas {
            return Err("o passo no anel 0 foi contado como falha");
        }
        Ok(())
    })
}

/// O `TF` ligado, o `mov ss` e a `syscall`: o processo morre do passo, e a
/// máquina segue. Num processador, o `mov ss` adia o `#DB` do passo até
/// depois da `syscall`, e ele chega no anel 0, na entrada; o kernel apaga o
/// `TF` do quadro e volta, a chamada roda, e o processo morre do passo no
/// anel 3, na volta, depois da `syscall`. O QEMU do TCG não adia o passo: o
/// `#DB` sai no anel 3 logo depois do `mov ss`, com o `rip` na `syscall`.
/// As duas formas valem.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_passo_adiado_pelo_mov_ss_mata_o_processo() -> Resultado {
    let passos = crate::traps::passos_do_anel_0();
    morre_pela_excecao(
        Excecao::MovSs,
        &[
            Esperada {
                nome: "debug",
                motivo: "depuracao",
                deslocamento: exemplo::NA_SYSCALL_DO_MOV_SS,
                codigo: do_passo,
                endereco: None,
            },
            Esperada {
                nome: "debug",
                motivo: "depuracao",
                deslocamento: exemplo::DEPOIS_DO_MOV_SS,
                codigo: do_passo,
                endereco: None,
            },
        ],
    )?;
    crate::log_info!(
        "teste",
        "excecoes: o passo do mov ss chegou ao anel 0 {} vez(es)",
        crate::traps::passos_do_anel_0() - passos
    );
    Ok(())
}

/// Roda `f` com o descritor da base do `sysret` marcado ausente — ver
/// `gdt::marcar_a_base_do_sysret_de_teste` —, e o devolve ao fim.
#[cfg(target_arch = "x86_64")]
fn com_a_base_do_sysret_ausente(f: impl FnOnce() -> Resultado) -> Resultado {
    const PRESENTE: u64 = 1 << 47;
    let antes = crate::arch::atual::gdt::marcar_a_base_do_sysret_de_teste(true);
    let resultado = f();
    crate::arch::atual::gdt::marcar_a_base_do_sysret_de_teste(false);
    if antes & PRESENTE == 0 {
        return Err("o descritor da base do sysret nao estava presente antes do caso");
    }
    resultado
}

/// O segmento ausente — o `mov ds` com 0x1B, o seletor da base do `sysret`,
/// cujo descritor o caso marca ausente — mata o processo pelo `#NP`, com o
/// seletor no código, em cada núcleo; o descritor volta ao fim. É o grupo
/// com código de erro alcançado do anel 3 no emulador: sem o caso, a
/// mutação que o devolve a fatal sobrevivia no lote B2 (ver *As mutações
/// das exceções*, no README).
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_segmento_ausente_mata_o_processo_pelo_np() -> Resultado {
    com_a_base_do_sysret_ausente(|| {
        morre_pela_excecao(
            Excecao::Ausente,
            &[Esperada {
                nome: "segment_not_present",
                motivo: "segmento ausente",
                deslocamento: exemplo::CARGA_DO_SELETOR,
                codigo: do_seletor_da_base_do_sysret,
                endereco: None,
            }],
        )
    })
}

/// O mesmo seletor no `SS`: o processo morre pelo `#SS`, com o seletor no
/// código, em cada núcleo.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_a_pilha_ausente_mata_o_processo_pelo_ss() -> Resultado {
    com_a_base_do_sysret_ausente(|| {
        morre_pela_excecao(
            Excecao::PilhaAusente,
            &[Esperada {
                nome: "stack_segment_fault",
                motivo: "falha de segmento de pilha",
                deslocamento: exemplo::CARGA_DO_SELETOR,
                codigo: do_seletor_da_base_do_sysret,
                endereco: None,
            }],
        )
    })
}

/// O `sysenter` do anel 3 mata o processo, em cada núcleo. Num Intel, ele
/// existe no modo de 64 bits e entraria no anel 0 pelo `IA32_SYSENTER_CS`
/// que o firmware deixasse; com ele em zero, é `#GP(0)`. Num AMD — e no
/// QEMU do TCG, com o `qemu64` —, é `#UD` no modo longo. As duas formas
/// valem.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_sysenter_do_anel_3_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Sysenter,
        &[
            Esperada {
                nome: "general_protection_fault",
                motivo: "falha de protecao",
                deslocamento: 0,
                codigo: zero,
                endereco: None,
            },
            Esperada {
                nome: "invalid_opcode",
                motivo: "instrucao invalida",
                deslocamento: 0,
                codigo: zero,
                endereco: None,
            },
        ],
    )
}

/// O `ESR_EL1` do acesso ao FP/SIMD preso pelo `CPACR_EL1`: a classe 0x07.
#[cfg(target_arch = "aarch64")]
fn do_fp_simd(codigo: u64) -> bool {
    (codigo >> 26) & 0x3F == 0x07
}

/// O FP/SIMD do EL0 — o `fmov` do `d0` — cai na classe 0x07, em cada
/// núcleo, duas vezes seguidas: o `CPACR_EL1` em zero em todo núcleo — o
/// `FPEN` em 00 — prende o FP/SIMD no EL0 e no EL1, e o processo morre na
/// primeira instrução. Antes, o kernel não escrevia o `CPACR_EL1`: no boot
/// cru ele sai do reset em zero, e o processo morria da classe 0x07 sem
/// nome (`sync_desconhecida`); pela UEFI, o EDK2 o deixa em 11, e o `d0`
/// que um processo deixava chegava ao seguinte no mesmo núcleo — a
/// primeira rodada saía com zero, a segunda com 1.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_fp_simd_do_el0_cai_na_classe_7_e_nao_passa_ao_seguinte() -> Resultado {
    o_simd_morre_e_nao_passa_ao_seguinte(&[Esperada {
        nome: "fp_simd_trap",
        motivo: "fp_simd_trap",
        deslocamento: 0,
        codigo: do_fp_simd,
        endereco: None,
    }])
}

/// O `ESR_EL1` do `msr daif, x0` preso pelo `SCTLR_EL1.UMA` desligado: a
/// classe 0x18, com o `DAIF` (`op0` 3, `op1` 3, `CRn` 4, `CRm` 2, `op2` 1),
/// escrito do `x0`.
#[cfg(target_arch = "aarch64")]
fn do_msr_do_daif(codigo: u64) -> bool {
    const ISS: u64 = (3 << 20) | (1 << 17) | (3 << 14) | (4 << 10) | (2 << 1);
    (codigo >> 26) & 0x3F == 0x18 && codigo & 0x3F_FFFF == ISS
}

/// O `msr daif` do EL0, com o `I` ligado, mata o processo, em cada núcleo:
/// o `SCTLR_EL1` que o kernel escreve inteiro tem o `UMA` desligado, e a
/// escrita é a exceção da classe 0x18. Com o `UMA` ligado — o que o
/// firmware deixasse, quando o kernel só ligava o `M`, o `C` e o `I` —, o
/// processo mascararia as IRQs do núcleo, e nenhum tique o tiraria dali.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_msr_daif_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Daif,
        &[Esperada {
            nome: "msr_mrs_trap",
            motivo: "msr_mrs_trap",
            deslocamento: exemplo::MSR_DO_DAIF,
            codigo: do_msr_do_daif,
            endereco: None,
        }],
    )
}

/// O `ESR_EL1` do `wfi` preso pelo `SCTLR_EL1.nTWI` desligado: a classe 0x01,
/// com o `TI` em 00 — o `wfi`, e não o `wfe`.
#[cfg(target_arch = "aarch64")]
fn do_wfi(codigo: u64) -> bool {
    (codigo >> 26) & 0x3F == 0x01 && codigo & 0b11 == 0
}

/// O `wfi` do EL0 mata o processo, em cada núcleo: o `SCTLR_EL1` do kernel
/// prende o `wfi` e o `wfe` do EL0 (a classe 0x01, `wfx_trap`), como o EDK2
/// já deixava, e o reset — o boot cru da suíte — não. Ligado, o `sev` de um
/// processo acordaria o `wfe` de outro, noutro núcleo: um sinal entre
/// processos por fora do gate (ver `mmu::SCTLR_DO_KERNEL`). O QEMU do TCG
/// não prende o `wfe` — ele o trata como um `yield` —, e o caso confere o
/// `wfi`: o programa o tenta quatro vezes, porque a arquitetura só prende o
/// que iria dormir, e com uma IRQ pendente ele passa.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_wfi_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Wfi,
        &[Esperada {
            nome: "wfx_trap",
            motivo: "wfx_trap",
            deslocamento: exemplo::WFI_DO_PROGRAMA,
            codigo: do_wfi,
            endereco: None,
        }],
    )
}

// ---------------------------------------------------------------------------
// O lote B3 do #448: o regime de cada núcleo e a pilha do `#MC`
// ---------------------------------------------------------------------------

/// O que o fio de [`conferir_o_regime`] viu no núcleo dele: o núcleo, mais
/// um — zero é "ainda não viu" —, quantas vezes o núcleo escreveu o regime
/// ao ligar, e três respostas num número só — o bit 0, o regime estava como
/// o kernel o escreve; o 1, o sujo não estava, e estava sujo inteiro; o 2, o
/// reescrito estava.
static REGIME_ONDE: AtomicU64 = AtomicU64::new(0);
static REGIME_ESCRITO: AtomicU64 = AtomicU64::new(0);
static REGIME_VISTO: AtomicU64 = AtomicU64::new(0);

/// O regime deste núcleo, lido, sujo e reescrito pela função do boot; as
/// três respostas de [`REGIME_VISTO`], e o log diz o regime e o que
/// divergiu, de cada um dos três.
#[cfg(target_arch = "x86_64")]
fn sujar_e_reescrever_o_regime(cpu: usize) -> (bool, bool, bool) {
    use crate::arch::atual as a;
    let antes = a::ler_o_regime_deste_nucleo();
    let (sujo, depois) = a::sujar_e_reescrever_o_regime_de_teste();
    crate::log_info!(
        "teste",
        "excecoes: o regime do nucleo {}: antes {:x?}; sujo {:x?}; depois {:x?}",
        cpu,
        antes,
        sujo,
        depois
    );
    o_que_divergiu(
        cpu,
        a::regime_como_o_kernel_escreve(&antes),
        a::regime_como_o_kernel_escreve(&sujo),
        a::regime_sujo_inteiro(&sujo),
        a::regime_como_o_kernel_escreve(&depois),
    )
}
#[cfg(target_arch = "aarch64")]
fn sujar_e_reescrever_o_regime(cpu: usize) -> (bool, bool, bool) {
    use crate::arch::atual::usuario as u;
    let antes = u::ler_o_regime_deste_nucleo();
    let (sujo, depois) = u::sujar_e_reescrever_o_regime_de_teste();
    crate::log_info!(
        "teste",
        "excecoes: o regime do nucleo {}: antes {:x?}; sujo {:x?}; depois {:x?}",
        cpu,
        antes,
        sujo,
        depois
    );
    o_que_divergiu(
        cpu,
        u::regime_como_o_kernel_escreve(antes),
        u::regime_como_o_kernel_escreve(sujo),
        u::regime_sujo_inteiro(sujo),
        u::regime_como_o_kernel_escreve(depois),
    )
}

/// O log do que divergiu do regime do kernel — antes, sujo e depois — e do
/// que não apareceu sujo, e as três respostas de [`REGIME_VISTO`]: o de
/// antes como o kernel o escreve; o sujo não, e sujo inteiro — cada item que
/// a suíte suja, sujo na leitura —; o de depois como o kernel o escreve.
/// Sem o sujo inteiro, bastava um item divergir — o `CR0` no x86, o
/// `SCTLR_EL1` no ARM, o primeiro que diverge —, e o "depois" provava a
/// reescrita só dos que apareceram sujos (o achado 2 do adversário do lote
/// B4 do #448).
fn o_que_divergiu(
    cpu: usize,
    antes: Result<(), &'static str>,
    sujo: Result<(), &'static str>,
    sujo_inteiro: Result<(), &'static str>,
    depois: Result<(), &'static str>,
) -> (bool, bool, bool) {
    crate::log_info!(
        "teste",
        "excecoes: o regime do nucleo {} contra o do kernel: antes {:?}; sujo {:?} (inteiro: \
         {:?}); depois {:?}",
        cpu,
        antes,
        sujo,
        sujo_inteiro,
        depois
    );
    (
        antes.is_ok(),
        sujo.is_err() && sujo_inteiro.is_ok(),
        depois.is_ok(),
    )
}

// Quantas vezes o núcleo `cpu` escreveu o regime.
#[cfg(target_arch = "x86_64")]
use crate::arch::atual::regimes_escritos_de_teste as regimes_escritos;
#[cfg(target_arch = "aarch64")]
use crate::arch::atual::usuario::regimes_escritos_de_teste as regimes_escritos;

extern "C" fn conferir_o_regime(_argumento: u64) -> ! {
    let cpu = crate::arch::nucleo_atual();
    REGIME_ESCRITO.store(regimes_escritos(cpu), SeqCst);
    let (antes, sujo, depois) = sujar_e_reescrever_o_regime(cpu);
    REGIME_VISTO.store(
        u64::from(antes) | (u64::from(sujo) << 1) | (u64::from(depois) << 2),
        SeqCst,
    );
    REGIME_ONDE.store(cpu as u64 + 1, SeqCst);
    crate::fios::terminar()
}

/// O regime de cada núcleo — o que vale para todo processo que roda nele, e
/// que o kernel escreve em vez de herdar do firmware (o item 2 e o item 10
/// do adversário do lote B2): no x86, o `CR0` com o `TS` e o `MP`, o `CR4`
/// do kernel, o `XCR0` do kernel, nenhum ponto de parada armado nem
/// endereçado, o `sysenter` sem entrada, e as bases do `FS` e do `GS` e o
/// `IA32_TSC_AUX` em zero; no ARM, o `CPACR_EL1` em zero, o `SCTLR_EL1` do
/// kernel, o `MDSCR_EL1` com o `TDCC` e o `TPIDRRO_EL0` em zero. Em cada
/// núcleo: o núcleo o escreveu ao ligar, ele está como o kernel o escreve,
/// e, sujo como um firmware o deixaria aberto — o `TS` e o `MP` desligados,
/// o `PGE`, o `PCE`, o `VME` e o `PVI` ligados, o `XCR0` só com o x87, um
/// ponto armado e os quatro endereços, o `sysenter` apontado para o anel 0,
/// as bases do `FS` e do `GS` fora de zero, uma marca no `IA32_TSC_AUX`; o
/// `FPEN` em 11, o `UMA`, o `DZE`, o `UCT` e o `UCI` ligados, o `MDSCR_EL1`
/// sem o `TDCC` e com o `MDE` e o `KDE`, uma marca no `TPIDRRO_EL0` —, a
/// função do boot o escreve de novo. Desde o lote B4, o `CR4` do x86 é
/// conferido bit a bit contra o CPUID, e não contra a função que o escreve
/// — a conferência tautológica deixava passar o `MCE` e o `DE` tirados
/// dela —, o log diz o primeiro que diverge, e o sujo tem de aparecer
/// inteiro na leitura, item por item, com o `SEP`, o `xsave`, o `RDTSCP` e
/// o `RDPID` do x86 pelo CPUID lido no próprio conferidor: antes, bastava um
/// item sujo, e uma pergunta errada pelo
/// `SEP` não sujava, não lia nem escrevia o `sysenter`, com o caso verde (o
/// achado 2 do adversário do lote B4). Os processos de verdade mostram o
/// efeito — o SSE, o x87, o `fwait` e o FP/SIMD presos, o `sysenter`, o
/// `msr daif`, o UMIP, o canal do depurador —; este caso mostra que é o
/// kernel quem escreve, e não o firmware que deixou: o reset e o OVMF já
/// deixam o `sysenter` e o `DR7` em repouso.
pub(super) fn excecoes_o_regime_de_cada_nucleo() -> Resultado {
    em_cada_nucleo(|cpu| {
        REGIME_ONDE.store(0, SeqCst);
        REGIME_ESCRITO.store(0, SeqCst);
        REGIME_VISTO.store(0, SeqCst);
        crate::fios::criar_no_nucleo("teste-excecao-regime", conferir_o_regime, 0, cpu)?;
        esperar_ate(|| REGIME_ONDE.load(SeqCst) != 0, 300)
            .map_err(|_| "o nucleo nao conferiu o proprio regime")?;
        if REGIME_ONDE.load(SeqCst) != cpu as u64 + 1 {
            return Err("o regime nao foi conferido no nucleo dele");
        }
        let visto = REGIME_VISTO.load(SeqCst);
        if REGIME_ESCRITO.load(SeqCst) == 0 {
            return Err("um nucleo ligado nao escreveu o regime ao ligar");
        }
        if visto & 1 == 0 {
            return Err("o regime do nucleo nao esta como o kernel o escreve");
        }
        if visto & 2 == 0 {
            return Err("o caso nao sujou o regime inteiro");
        }
        if visto & 4 == 0 {
            return Err("o kernel nao reescreveu o regime que outro deixou aberto");
        }
        Ok(())
    })
}

/// O `#MC` tem uma pilha da IST só dele, em cada núcleo, separada da do
/// `#DF`, da NMI e do `#DB` (o item 6 do adversário do lote B2): um `#MC` no
/// meio do post-mortem de um `#DF`, ou o contrário, recomeçava a pilha
/// dividida por cima do relatório em curso. O portão do vetor 18 na IDT
/// carregada aponta um índice que nenhum dos outros três usa, e o TSS de
/// cada núcleo tem, nesse índice, um topo próprio — diferente do do `#DF`
/// do mesmo núcleo e do do `#MC` de todo outro.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_mc_tem_pilha_propria() -> Resultado {
    use crate::arch::atual::{gdt, idt};
    let ist = |vetor| idt::ist_do_vetor_de_teste(vetor);
    let (db, nmi, df, mc) = (ist(1), ist(2), ist(8), ist(18));
    crate::log_info!(
        "teste",
        "excecoes: os portoes da IDT na IST: #DB {}, NMI {}, #DF {}, #MC {}",
        db,
        nmi,
        df,
        mc
    );
    if mc == 0 {
        return Err("o portao do #MC nao tem pilha da IST");
    }
    if [db, nmi, df].contains(&mc) {
        return Err("o #MC divide a pilha da IST com outro portao");
    }
    let mut topos = alloc::vec::Vec::new();
    for cpu in nucleos() {
        let do_mc = gdt::topo_da_ist_de_teste(cpu, usize::from(mc) - 1);
        let do_df = gdt::topo_da_ist_de_teste(cpu, usize::from(df) - 1);
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o topo da pilha do #MC {:#x}, o do #DF {:#x}",
            cpu,
            do_mc,
            do_df
        );
        if do_mc == 0 || do_mc == do_df {
            return Err("o #MC de um nucleo nao tem pilha propria, separada da do #DF");
        }
        topos.push(do_mc);
    }
    topos.sort_unstable();
    topos.dedup();
    if topos.len() != nucleos().len() {
        return Err("dois nucleos dividem a pilha do #MC");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// O lote B4 do #448: o estado por fio, os registradores da entrada, o UMIP,
// o `fwait` e o canal do depurador
// ---------------------------------------------------------------------------

/// O programa do canal `e` roda duas vezes seguidas no núcleo, em cada
/// núcleo ligado, e sai com zero as duas: o registrador que a primeira
/// rodada deixa não chega à segunda — o processo novo o recebe nulo. Antes,
/// o kernel não guardava o registrador por fio, e ele ficava no núcleo de
/// um processo para o seguinte: a segunda rodada lia a marca da primeira e
/// saía com [`exemplo::CODIGO_DO_CANAL`]. As duas rodam sempre, e o log diz
/// como cada uma acabou.
fn o_registrador_nao_passa_ao_seguinte(e: Excecao) -> Resultado {
    em_cada_nucleo(|cpu| {
        let mut saidas = [None; 2];
        for saida in &mut saidas {
            crate::usuario::limpar_ultima_saida();
            let falhas = crate::traps::total();
            let id = rodar(e, cpu)?;
            if crate::traps::total() != falhas {
                return Err("uma falha foi contada para o programa do canal");
            }
            *saida = crate::usuario::ultima_saida();
            fora_da_tabela_e_o_nucleo_segue(id, cpu)?;
        }
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o canal de {:?}: a primeira rodada saiu com {:?}, a segunda \
             com {:?}",
            cpu,
            e,
            saidas[0],
            saidas[1]
        );
        if saidas[1] == Some(exemplo::CODIGO_DO_CANAL) {
            return Err(
                "o canal: a segunda rodada no mesmo nucleo leu o registrador que a primeira deixou",
            );
        }
        if saidas != [Some(0), Some(0)] {
            return Err("o programa do canal nao saiu com zero");
        }
        Ok(())
    })
}

/// O `FS` — o seletor que um ambiente de execução usaria para a área local
/// de cada fio — e, depois, os quatro seletores de dados, o `DS`, o `ES`, o
/// `FS` e o `GS`, não chegam de um processo ao seguinte no mesmo núcleo (o
/// item 2 do adversário do lote B3): o kernel os guarda por fio, na troca de
/// contexto, e o fio novo os recebe nulos. Antes, a troca não os tocava, e o
/// retorno ao anel 3 só anula um seletor de privilégio maior que o dele: a
/// marca que um processo deixava, o seguinte lia.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_os_seletores_de_um_processo_nao_chegam_ao_seguinte() -> Resultado {
    let fs = o_registrador_nao_passa_ao_seguinte(Excecao::CanalFs);
    let todos = o_registrador_nao_passa_ao_seguinte(Excecao::CanalSeletores);
    fs.and(todos)
}

/// O `TPIDR_EL0` — o registrador que o EL0 escreve e lê sem armadilha que o
/// EL1 possa ligar, e que um ambiente de execução usa para a área local de
/// cada fio — não chega de um processo ao seguinte no mesmo núcleo (o item
/// 1 do adversário do lote B3): o kernel o guarda por fio, na troca de
/// contexto, e o fio novo o recebe zerado. Antes, ninguém o tocava: a marca
/// que um processo deixava, o seguinte lia.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_tpidr_el0_de_um_processo_nao_chega_ao_seguinte() -> Resultado {
    o_registrador_nao_passa_ao_seguinte(Excecao::CanalTpidr)
}

/// Quantos dos dois hospedeiros do par já carregaram o programa.
static PAR_CARREGADOS: AtomicU64 = AtomicU64::new(0);

/// Um dos dois hospedeiros do par não carregou o programa, ou não entrou
/// com ele no anel sem privilégio. Ele conta como carregado mesmo assim:
/// sem isso, o outro cederia para sempre à espera dele, preso ao núcleo,
/// pelo resto da suíte.
static PAR_FALHOU: AtomicBool = AtomicBool::new(false);

/// O mínimo de trocas diretas entre o receptor e o emissor, num núcleo, para
/// o caso do par valer: revezando-se, eles passam a vez um ao outro a cada
/// `ceder` — umas 128 vezes, ou umas 64 com o executor da suíte no mesmo
/// núcleo, entre os dois —; sem se revezar, nenhuma.
const TROCAS_MINIMAS_DO_PAR: u64 = 16;

/// Em que núcleo cada um do par rodou — o receptor, o emissor —, ou
/// `u64::MAX`.
static PAR_ONDE: [AtomicU64; 2] = [const { AtomicU64::new(u64::MAX) }; 2];

/// O hospedeiro do par: carrega o programa — `argumento` traz o papel nos 32
/// bits de cima e o índice em [`PROGRAMAS`] nos de baixo — e só entra no
/// anel sem privilégio quando o outro também carregou, cedendo até lá. Os
/// dois estão presos ao mesmo núcleo: dali em diante, cada `ceder` de um
/// passa a vez ao outro, e o caso não depende de quem carregou primeiro —
/// sem a barreira, o emissor podia ceder as 64 vezes antes de o receptor
/// existir, e o caso passaria sem ter provado nada.
extern "C" fn hospedar_em_par(argumento: u64) -> ! {
    let (papel, indice) = (
        (argumento >> 32) as usize,
        (argumento & 0xFFFF_FFFF) as usize,
    );
    PAR_ONDE[papel].store(crate::arch::nucleo_atual() as u64, SeqCst);
    let imagem = exemplo::bytes_da_excecao(PROGRAMAS[indice]);
    let programa = match crate::usuario::programa::carregar_de_teste(imagem, None) {
        Ok(p) => p,
        Err(falha) => {
            crate::log_error!(
                "teste",
                "o programa do par nao carregou: {}",
                falha.motivo()
            );
            PAR_FALHOU.store(true, SeqCst);
            PAR_CARREGADOS.fetch_add(1, SeqCst);
            crate::fios::terminar()
        }
    };
    PAR_CARREGADOS.fetch_add(1, SeqCst);
    while PAR_CARREGADOS.load(SeqCst) < 2 {
        crate::fios::ceder();
    }
    match crate::usuario::programa::entrar_de_teste(programa) {
        Ok(_) => unreachable!("entrar nao retorna em caso de sucesso"),
        Err(falha) => {
            crate::log_error!(
                "teste",
                "nao foi possivel entrar em userspace: {}",
                falha.motivo()
            );
            PAR_FALHOU.store(true, SeqCst);
            crate::fios::terminar()
        }
    }
}

/// O par, em cada núcleo ligado: o `receptor` e o `emissor`, presos ao
/// núcleo e entrados juntos, cedem um ao outro 64 vezes; o receptor confere,
/// a cada volta, que o registrador ainda é o dele — se não, morre de uma
/// falha (o `ud2`, o `brk #1`), que a contabilidade conta, e a ordem das
/// duas saídas não importa. Reprova o kernel que não guarda o registrador, e
/// também o que o zera a cada troca: o receptor perderia o dele. O caso
/// confere que os dois rodaram no núcleo, que cederam as vezes todas e que
/// se revezaram — o escalonador conta as trocas diretas de um ao outro
/// (`fios::vigiar_o_par_de_teste`) —: sem isso, passaria sem ter provado
/// nada. Antes, a vez só se provava pelas mutações, e não pelo caso (um
/// informativo do adversário do lote B4 do #448).
fn o_registrador_fica_com_quem_o_escreveu(receptor: Excecao, emissor: Excecao) -> Resultado {
    let posicao = |e| PROGRAMAS.iter().position(|&p| p == e);
    let ir = posicao(receptor).ok_or("o receptor nao esta na tabela do caso")? as u64;
    let ie = posicao(emissor).ok_or("o emissor nao esta na tabela do caso")? as u64;
    em_cada_nucleo(|cpu| {
        PAR_CARREGADOS.store(0, SeqCst);
        PAR_FALHOU.store(false, SeqCst);
        for onde in &PAR_ONDE {
            onde.store(u64::MAX, SeqCst);
        }
        let falhas = crate::traps::total();
        let chamadas = crate::usuario::estatisticas().0;
        let id_r =
            crate::fios::criar_no_nucleo("teste-par-receptor", hospedar_em_par, ir, cpu)?.numero();
        let id_e = crate::fios::criar_no_nucleo(
            "teste-par-emissor",
            hospedar_em_par,
            (1 << 32) | ie,
            cpu,
        )?
        .numero();
        // As trocas contam a partir daqui; as poucas que o par fizer antes,
        // entre a criação dos dois e esta linha, ficam de fora.
        crate::fios::vigiar_o_par_de_teste(id_r, id_e);
        let acabaram = esperar_ate(|| !crate::fios::vivo(id_r) && !crate::fios::vivo(id_e), 600);
        let trocas = crate::fios::vigiar_o_par_de_teste(0, 0);
        acabaram.map_err(|_| "o receptor e o emissor nao acabaram")?;
        let contadas = crate::traps::total() - falhas;
        let chamadas = crate::usuario::estatisticas().0 - chamadas;
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o par de {:?}: {} falha(s), {} chamada(s), {} troca(s) \
             direta(s) entre os dois",
            cpu,
            receptor,
            contadas,
            chamadas,
            trocas
        );
        if PAR_FALHOU.load(SeqCst) {
            return Err("um programa do par nao carregou ou nao entrou no anel sem privilegio");
        }
        if contadas != 0
            && let Some(falha) = crate::traps::ultima()
        {
            crate::log_error!(
                "teste",
                "{} em pc={:#x}, codigo {:#x}",
                falha.nome,
                falha.pc,
                falha.codigo
            );
        }
        if PAR_ONDE.iter().any(|o| o.load(SeqCst) != cpu as u64) {
            return Err("o par nao rodou no nucleo dele");
        }
        if contadas != 0 {
            return Err("o registrador do receptor mudou enquanto ele cedia ao emissor");
        }
        // As 64 cessões de cada um e as duas saídas, no mínimo.
        if chamadas < 2 * 65 {
            return Err("o receptor e o emissor nao cederam as vezes todas");
        }
        if trocas < TROCAS_MINIMAS_DO_PAR {
            return Err("o receptor e o emissor nao se revezaram no nucleo");
        }
        fora_da_tabela_e_o_nucleo_segue(id_r, cpu)?;
        fora_da_tabela_e_o_nucleo_segue(id_e, cpu)
    })
}

/// Os quatro seletores de dados ficam com o processo que os escreveu, entre
/// as trocas de contexto — ver [`o_registrador_fica_com_quem_o_escreveu`].
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_os_seletores_ficam_com_o_processo_que_os_escreveu() -> Resultado {
    o_registrador_fica_com_quem_o_escreveu(Excecao::SeletoresReceptor, Excecao::SeletoresEmissor)
}

/// O `TPIDR_EL0` fica com o processo que o escreveu, entre as trocas de
/// contexto — ver [`o_registrador_fica_com_quem_o_escreveu`].
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_tpidr_el0_fica_com_o_processo_que_o_escreveu() -> Resultado {
    o_registrador_fica_com_quem_o_escreveu(Excecao::TpidrReceptor, Excecao::TpidrEmissor)
}

/// Os registradores do processo novo chegam zerados, em cada núcleo (o item
/// 5 do adversário do lote B3): os gerais — menos a pilha que o carregador
/// dá — e, no x86, os quatro seletores de dados; no ARM, o `TPIDR_EL0` e o
/// `TPIDRRO_EL0`. Antes, a primeira entrada no anel sem privilégio levava o
/// que o kernel tinha deixado neles — endereços do kernel, entre outros.
pub(super) fn excecoes_os_registradores_do_processo_novo_chegam_zerados() -> Resultado {
    em_cada_nucleo(|cpu| {
        crate::usuario::limpar_ultima_saida();
        let falhas = crate::traps::total();
        let id = rodar(Excecao::Registradores, cpu)?;
        let saida = crate::usuario::ultima_saida();
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, o programa dos registradores saiu com {:?}",
            cpu,
            saida
        );
        if crate::traps::total() != falhas {
            return Err("uma falha foi contada para o programa dos registradores");
        }
        if saida != Some(0) {
            return Err("um registrador chegou ao processo novo com o que o kernel deixou");
        }
        fora_da_tabela_e_o_nucleo_segue(id, cpu)
    })
}

/// O filho do `fork` herda o estado por fio do pai — os seletores de dados
/// no x86, o `TPIDR_EL0` no ARM —, como herda os registradores gerais; e a
/// troca de imagem o zera, como zera o resto: a imagem nova não tem direito
/// ao estado da que saiu. O pai deixa as marcas e bifurca; o filho as
/// confere e troca de imagem pelo `filho`, que as confere nulas antes de
/// escrever — e as flags, as de um processo novo. O pai sai com o código do
/// filho: o 24 de sempre, ou [`exemplo::CODIGO_SEM_HERANCA`] ou
/// [`exemplo::CODIGO_DO_FILHO_SUJO`].
pub(super) fn excecoes_o_fork_herda_o_estado_por_fio_e_a_troca_de_imagem_o_zera() -> Resultado {
    em_cada_nucleo(|cpu| {
        crate::usuario::limpar_ultima_saida();
        let falhas = crate::traps::total();
        let (bifurcacoes, trocas, _) = crate::usuario::estatisticas_de_processo();
        let id = rodar(Excecao::Heranca, cpu)?;
        let saida = crate::usuario::ultima_saida();
        let (b, t, _) = crate::usuario::estatisticas_de_processo();
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, a heranca: o pai saiu com {:?}; {} bifurcacao(oes), {} \
             troca(s) de imagem",
            cpu,
            saida,
            b - bifurcacoes,
            t - trocas
        );
        if crate::traps::total() != falhas {
            return Err("uma falha foi contada no caso da heranca");
        }
        match saida {
            Some(exemplo::CODIGO_SEM_HERANCA) => {
                return Err("o filho do fork nao recebeu o estado por fio do pai");
            }
            Some(exemplo::CODIGO_DO_FILHO_SUJO) => {
                return Err("a imagem nova recebeu o estado por fio, ou as flags, da que saiu");
            }
            Some(exemplo::CODIGO_DO_FILHO) => {}
            _ => return Err("o pai nao saiu com o codigo do filho"),
        }
        if b != bifurcacoes + 1 || t != trocas + 1 {
            return Err("o processo nao bifurcou e trocou de imagem uma vez cada");
        }
        fora_da_tabela_e_o_nucleo_segue(id, cpu)
    })
}

/// A morte pelo `#GP` com o código zero, na instrução da entrada.
#[cfg(target_arch = "x86_64")]
const PELO_GP_ZERO: Formas = &[Esperada {
    nome: "general_protection_fault",
    motivo: "falha de protecao",
    deslocamento: 0,
    codigo: zero,
    endereco: None,
}];

/// O `str`, o `sldt`, o `smsw`, o `sgdt` e o `sidt` do anel 3 morrem do
/// `#GP(0)`, em cada núcleo (o item 6 do adversário do lote B3): o
/// `CR4.UMIP` ligado, quando o processador o declara. Sem ele, diziam ao
/// processo o seletor do TSS do núcleo, o do LDT, o `CR0` baixo e onde estão
/// a GDT e a IDT do kernel — o endereço de estruturas do kernel, que o
/// processo não tem por que saber. A suíte roda com o `+umip` no `-cpu`
/// (`xtask`): sem ele, o caso diz que a máquina não o oferece e não afirma
/// nada, como o do SMEP.
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_as_instrucoes_do_umip_matam_o_processo() -> Resultado {
    let (tem, ligado) = crate::arch::atual::umip_de_teste();
    if !tem {
        crate::log_warn!("teste", "esta cpu nao oferece UMIP; nada a afirmar");
        return Ok(());
    }
    let mut primeiro = if ligado {
        Ok(())
    } else {
        crate::log_error!("teste", "excecoes: a cpu oferece UMIP e o CR4 nao o tem");
        Err("a cpu oferece UMIP e o kernel nao o ligou")
    };
    for e in [
        Excecao::Str,
        Excecao::Sldt,
        Excecao::Smsw,
        Excecao::Sgdt,
        Excecao::Sidt,
    ] {
        if let Err(motivo) = morre_pela_excecao(e, PELO_GP_ZERO) {
            crate::log_error!("teste", "excecoes: o {:?}: {}", e, motivo);
            if primeiro.is_ok() {
                primeiro = Err(motivo);
            }
        }
    }
    primeiro
}

/// O `fwait` do anel 3 cai no `#NM`, em cada núcleo: o `CR0.MP` ligado, com
/// o `TS`, o prende como prende o x87. Sem o `MP`, ele só conferiria as
/// exceções do x87 pendentes, e o processo seguiria — o `MP` é o que o
/// distingue (o item 7 do adversário do lote B3: tirá-lo não reprovava
/// nada).
#[cfg(target_arch = "x86_64")]
pub(super) fn excecoes_o_fwait_do_anel_3_cai_no_nm() -> Resultado {
    morre_pela_excecao(Excecao::Fwait, PELO_NM)
}

/// O `ESR_EL1` do `mrs x0, mdccsr_el0` preso pelo `MDSCR_EL1.TDCC`: a classe
/// 0x18, com o `MDCCSR_EL0` (`op0` 2, `op1` 3, `CRn` 0, `CRm` 1, `op2` 0),
/// lido para o `x0`.
#[cfg(target_arch = "aarch64")]
fn do_mrs_do_mdccsr(codigo: u64) -> bool {
    const ISS: u64 = (2 << 20) | (3 << 14) | (1 << 1) | 1;
    (codigo >> 26) & 0x3F == 0x18 && codigo & 0x3F_FFFF == ISS
}

/// O EL0 que lê o canal do depurador — o `MDCCSR_EL0` — morre, em cada
/// núcleo (o item 8 do adversário do lote B3): o `MDSCR_EL1.TDCC` que o
/// kernel liga prende o canal do depurador no EL0, a classe 0x18. Sem ele,
/// o `TXfull` que um processo ligasse escrevendo o `DBGDTRTX_EL0`, o
/// seguinte veria — um canal entre processos, por fora do gate.
#[cfg(target_arch = "aarch64")]
pub(super) fn excecoes_o_canal_do_depurador_do_el0_mata_o_processo() -> Resultado {
    morre_pela_excecao(
        Excecao::Mdccsr,
        &[Esperada {
            nome: "msr_mrs_trap",
            motivo: "msr_mrs_trap",
            deslocamento: 0,
            codigo: do_mrs_do_mdccsr,
            endereco: None,
        }],
    )
}

/// A troca de imagem entrega à imagem nova as flags de um processo novo — no
/// x86, o `RFLAGS` 0x202 do `entrar`; no ARM, o `NZCV` em zero do
/// `SPSR_USUARIO` —, e não as da imagem que saiu (o achado 1 do adversário do
/// lote B4). O programa liga o `DF` e o `CF` (x86) ou o `N`, o `Z`, o `C` e
/// o `V` (ARM) e troca de imagem pelo `filho`, que confere as flags antes de
/// qualquer instrução que as mude e sai com [`exemplo::CODIGO_DO_FILHO_SUJO`]
/// se vieram da anterior. Antes, a troca de imagem guardava o `R11` — o
/// `RFLAGS` da `syscall` do `executar` — e o `SPSR` da chamada: com o `DF`
/// herdado, o `memset` e o `memcpy` de todo programa do contrato andariam
/// para trás. O `filho` confere as flags em toda troca de imagem da suíte
/// que passa por ele — a do `exemplo`, a do `NT` e a da herança também.
pub(super) fn excecoes_a_troca_de_imagem_nao_entrega_as_flags_da_anterior() -> Resultado {
    em_cada_nucleo(|cpu| {
        crate::usuario::limpar_ultima_saida();
        let falhas = crate::traps::total();
        let (_, trocas, _) = crate::usuario::estatisticas_de_processo();
        let id = rodar(Excecao::TrocaComFlags, cpu)?;
        let saida = crate::usuario::ultima_saida();
        let (_, t, _) = crate::usuario::estatisticas_de_processo();
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, a troca de imagem com as flags ligadas: o filho saiu com {:?}",
            cpu,
            saida
        );
        if crate::traps::total() != falhas {
            return Err("uma falha foi contada na troca de imagem com as flags ligadas");
        }
        if t != trocas + 1 {
            return Err("o processo nao trocou de imagem");
        }
        match saida {
            Some(exemplo::CODIGO_DO_FILHO) => {}
            Some(exemplo::CODIGO_DO_FILHO_SUJO) => {
                return Err("a imagem nova recebeu as flags da que saiu");
            }
            _ => return Err("o processo nao saiu com o codigo do filho"),
        }
        fora_da_tabela_e_o_nucleo_segue(id, cpu)
    })
}
