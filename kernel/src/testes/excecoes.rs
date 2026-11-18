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
//! Dois desses o QEMU do TCG (8.2) não reproduz como o processador: o `int1`
//! é um `#UD`, e o `push` não canônico, uma falha de página no endereço
//! truncado. O caso aceita as duas formas, a do processador e a do emulador,
//! e diz qual é qual; o `#DB` do anel 3 no emulador é o dos casos do passo.
//! As outras exceções com código de erro — `#TS`, `#NP`, `#AC`, `#CP`,
//! `#VC`, `#SX` — e o `#NM`, o `#OF`, o `#BR`, o `#VE` e o `#HV` não se
//! alcançam do anel 3 no emulador, com o que o kernel liga: os tratadores
//! delas usam a mesma regra (`arch::x86_64::idt`), e o `#GP` e a
//! falha de página, que a usam também, são exercitados aqui e no `contador`.
//! O `#MF` e o `#XM` podem se alcançar do anel 3 — o x87 ou o `MXCSR`
//! desmascarados —, sem caso: usam o tratador do grupo sem código de erro,
//! que o caso do `ud2` confere.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

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
    #[cfg(target_arch = "aarch64")]
    Excecao::BrkDoEstouro,
    #[cfg(target_arch = "aarch64")]
    Excecao::BrkDaBorda,
    #[cfg(target_arch = "aarch64")]
    Excecao::Brk,
];

/// O hospedeiro: anota o núcleo e entra no anel sem privilégio com o
/// programa da vez. Não volta: o processo morre da exceção, ou sai.
extern "C" fn hospedar(indice: u64) -> ! {
    RODOU.store(crate::arch::nucleo_atual() as u64, SeqCst);
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
    let entrada = entrada_de(exemplo::bytes_da_excecao(e))?;
    for cpu in nucleos() {
        crate::usuario::limpar_ultima_saida();
        let falhas = crate::traps::total();
        let desde = crate::log::total_emitidos();
        let id = rodar(e, cpu)?;
        if crate::usuario::ultima_saida() == Some(exemplo::CODIGO_DA_EXCECAO) {
            return Err("o processo seguiu depois da excecao");
        }
        if crate::traps::total() <= falhas {
            return Err("a excecao do processo nao foi contada");
        }
        let falha = crate::traps::ultima().ok_or("a falha da excecao nao foi contada")?;
        crate::log_info!(
            "teste",
            "excecoes: no nucleo {}, {} em pc={:#x}, codigo {:#x}",
            cpu,
            falha.nome,
            falha.pc,
            falha.codigo
        );
        let Some(esperada) = formas.iter().find(|f| {
            falha.nome == f.nome && falha.pc == entrada + f.deslocamento && (f.codigo)(falha.codigo)
        }) else {
            for f in formas {
                crate::log_error!(
                    "teste",
                    "esperada {} em pc={:#x}",
                    f.nome,
                    entrada + f.deslocamento
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
        fora_da_tabela_e_o_nucleo_segue(id, cpu)?;
    }
    Ok(())
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
            },
            Esperada {
                nome: "invalid_opcode",
                motivo: "instrucao invalida",
                deslocamento: 0,
                codigo: zero,
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
        }],
    )
}

/// O `push` com o `rsp` não canônico: o processo morre, no `push`. Num
/// processador, de `#SS` com o código zero — a referência à pilha num
/// endereço não canônico —, que antes do lote B2 ia pela entrada ausente ao
/// `#NP` e ao `#DF`, fatal. O QEMU do TCG (8.2) não confere a forma
/// canônica nesse acesso: a escrita vai ao endereço truncado, e é uma falha
/// de página no zero, com o código de uma escrita do anel 3 numa página
/// ausente — a rodada antes da correção o mostrou. As duas formas valem.
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
            },
            Esperada {
                nome: "page_fault",
                motivo: "falha de pagina",
                deslocamento: exemplo::PUSH_DA_PILHA,
                codigo: escrita_do_anel_3_sem_pagina,
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
/// contada, o companheiro volta à vez, e o processo sai da tabela.
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
            if crate::usuario::ultima_saida() != Some(exemplo::CODIGO_DO_FILHO) {
                return Err("o processo com o NT nao trocou de imagem e saiu pelo filho");
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
        }],
    )
}
