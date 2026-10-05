//! Vários núcleos no x86: acordar, avisar e parar.
//!
//! # Acordar
//!
//! Um núcleo de aplicação de um PC acorda como um 8086: em **modo real**, de
//! 16 bits, sem paginação, executando a partir de uma página abaixo de 1 MiB
//! cujo número vai no sinal de partida. É a herança mais funda do x86, e não
//! há como pular: o primeiro código que ele roda precisa estar lá embaixo, e
//! precisa ser de 16 bits.
//!
//! Este módulo põe ali um trampolim curto que faz, em sequência, o que o
//! firmware e o iniciador fizeram pelo primeiro núcleo:
//!
//! 1. carrega uma GDT provisória com um segmento de código de 64 bits;
//! 2. liga `PAE`, aponta o `CR3` para uma tabela provisória, liga `LME` e
//!    `NXE` no `EFER`;
//! 3. liga proteção e paginação **de uma vez** — o que leva o processador
//!    direto ao modo longo, sem passar pelo modo protegido de 32 bits;
//! 4. salta para o segmento de 64 bits, adota a pilha do fio ocioso e salta
//!    para [`entrada_secundaria`], na metade alta, em Rust.
//!
//! A tabela provisória é uma cópia da raiz do kernel com uma entrada a mais:
//! a identidade dos primeiros 2 MiB, onde o trampolim está. Sem ela, a
//! instrução seguinte à que liga a paginação não teria tradução. A raiz do
//! kernel não pode servir direto por dois motivos: ela não tem essa
//! identidade (foi largada no boot, de propósito) e o `CR3` é carregado em
//! 32 bits, então a raiz precisa estar abaixo de 4 GiB — a provisória mora na
//! segunda página baixa.
//!
//! # Avisar
//!
//! Por NMI, e só por NMI. Os dois avisos que um núcleo precisa dar aos outros
//! têm de chegar a um núcleo que esteja girando numa trava com as
//! interrupções desligadas — que é justamente o estado em que ele espera por
//! quem está mandando o aviso:
//!
//! - **uma tradução do kernel morreu.** Quem desmapeia uma página do kernel
//!   segura a trava da paginação; um núcleo que queira mapear algo gira
//!   nessa trava, mascarado. Se o aviso fosse uma interrupção comum, ele não
//!   o receberia, quem avisa não soltaria a trava antes da confirmação, e os
//!   dois esperariam um pelo outro para sempre;
//! - **o sistema parou.** O caminho de falha fatal destrava à força todas as
//!   travas do kernel para poder relatar; um núcleo que continuasse rodando
//!   entraria nelas junto com o relatório.
//!
//! # O que não precisa de aviso
//!
//! Desmapear uma página **do processo**. Um processo tem um fio só, e um fio
//! roda num núcleo de cada vez; os núcleos por onde ele passou antes
//! trocaram de `CR3` ao largá-lo, e trocar de `CR3` descarta as traduções do
//! usuário. Ver [`super::paginacao::desmapear`].

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::trava::Mutex;
use x86_64::structures::paging::PageTable;

use super::{apic, gdt, idt, paginacao, usuario};
use crate::nucleos::MAX_NUCLEOS;

// ---------------------------------------------------------------------------
// O trampolim
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.section .rodata.partida, "a"
.balign 16
.global partida_inicio
partida_inicio:
.code16
    cli
    cld
    // Em modo real os endereços são segmento * 16 + deslocamento. O SIPI
    // põe CS na página do trampolim e IP em zero, então com DS = CS cada
    // rótulo é alcançado pelo seu deslocamento a partir do começo — que é
    // o que as subtrações abaixo calculam, na montagem.
    movw %cs, %ax
    movw %ax, %ds

    lgdtl (partida_gdtr - partida_inicio)

    // PAE: o modo longo só existe com tabelas de 64 bits.
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    movl (partida_cr3 - partida_inicio), %eax
    movl %eax, %cr3

    // EFER: LME (bit 8), que pede o modo longo, e NXE (bit 11), sem o qual o
    // bit 63 das entradas do kernel é reservado — e uma página marcada como
    // não executável viraria uma falha de página na primeira busca.
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x900, %eax
    wrmsr

    // PE e PG juntos: com LME ligado, isto ativa o modo longo direto.
    movl %cr0, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0

    // O salto longo é o que troca CS pelo segmento de 64 bits. O destino é
    // um endereço absoluto, escrito em `partida_salto` por quem preparou a
    // página: depende de onde ela está.
    ljmpl *(partida_salto - partida_inicio)

.code64
partida_64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    // Relativo ao RIP, que aqui é o endereço baixo de identidade: a
    // distância até os dados é a mesma da imagem, porque a página foi
    // copiada inteira.
    movq partida_pilha(%rip), %rsp
    // Um endereço de retorno falso: a entrada em Rust espera a pilha como
    // ela fica depois de um `call`, desalinhada de oito.
    pushq $0
    movq partida_nucleo(%rip), %rdi
    movq partida_entrada(%rip), %rax
    jmpq *%rax

.balign 8
partida_gdt:
    .quad 0
    .quad 0x00AF9A000000FFFF
    .quad 0x00CF92000000FFFF
partida_gdtr:
    .word 23
    .long 0
.balign 8
partida_salto:
    .long 0
    .word 0x08
.balign 8
.global partida_cr3
partida_cr3:
    .quad 0
.global partida_pilha
partida_pilha:
    .quad 0
.global partida_nucleo
partida_nucleo:
    .quad 0
.global partida_entrada
partida_entrada:
    .quad 0
.global partida_fim
partida_fim:
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static partida_inicio: u8;
    static partida_64: u8;
    static partida_gdt: u8;
    static partida_gdtr: u8;
    static partida_salto: u8;
    static partida_cr3: u8;
    static partida_pilha: u8;
    static partida_nucleo: u8;
    static partida_entrada: u8;
    static partida_fim: u8;
}

/// O deslocamento de um rótulo do trampolim a partir do começo dele.
fn deslocamento(rotulo: *const u8) -> u64 {
    rotulo as u64 - (&raw const partida_inicio) as u64
}

/// As duas páginas baixas: a primeira recebe o trampolim, a segunda a raiz
/// provisória. Zero quando não há.
static PAGINAS_BAIXAS: AtomicU64 = AtomicU64::new(0);

/// Escolhe duas páginas utilizáveis abaixo de 1 MiB para a partida, e as
/// tira do alocador de frames.
///
/// Chamada por [`super::reservar_faixas`], antes de qualquer frame ser
/// entregue: depois disso, as páginas baixas podem já ter dono.
///
/// # Por que as mais altas
///
/// As mais baixas do primeiro mebibyte são as de mais história — a tabela
/// de vetores do BIOS no zero, a área de dados dele logo depois. O mapa da
/// UEFI não as entrega como utilizáveis, mas preferir as de cima é não
/// precisar confiar nisso.
pub fn reservar_paginas_baixas(mut reservar: impl FnMut(u64, u64)) {
    const LIMITE: u64 = 0x10_0000;
    const PRIMEIRA: u64 = 0x1000;
    let mut escolha = 0u64;
    crate::machine::com_regioes(|r| {
        if r.tipo != crate::machine::TipoRegiao::Utilizavel {
            return;
        }
        let inicio = r.inicio.max(PRIMEIRA).next_multiple_of(4096);
        let fim = r.fim.min(LIMITE) & !0xFFF;
        if fim >= inicio + 2 * 4096 {
            escolha = escolha.max(fim - 2 * 4096);
        }
    });
    if escolha == 0 {
        crate::log_warn!(
            "smp",
            "nenhuma pagina livre abaixo de 1 MiB: os demais nucleos nao vao acordar"
        );
        return;
    }
    reservar(escolha, escolha + 2 * 4096);
    PAGINAS_BAIXAS.store(escolha, Ordering::Release);
}

/// O que um núcleo novo copia do primeiro, porque não tem como descobrir
/// sozinho.
struct Molde {
    cr0: AtomicU64,
    cr4: AtomicU64,
    pat: AtomicU64,
    xcr0: AtomicU64,
}

static MOLDE: Molde = Molde {
    cr0: AtomicU64::new(0),
    cr4: AtomicU64::new(0),
    pat: AtomicU64::new(0),
    xcr0: AtomicU64::new(0),
};

/// O MSR da tabela de atributos de página.
const IA32_PAT: u32 = 0x277;
/// O bit do `CR4` que liga `xsave`/`xgetbv`.
const CR4_OSXSAVE: u64 = 1 << 18;

/// Fotografa os registradores de controle do primeiro núcleo.
///
/// O `CR0` e o `CR4` dizem o regime em que o kernel roda: proteção de escrita
/// no anel zero, SMEP, SSE habilitado. Um núcleo que acordasse com os valores
/// de reset seria um núcleo com proteções a menos — e o primeiro processo
/// que rodasse nele usaria SSE e morreria de `#UD`.
fn fotografar() {
    use x86_64::registers::control::{Cr0, Cr4};
    let cr4 = Cr4::read_raw();
    MOLDE.cr0.store(Cr0::read_raw(), Ordering::Relaxed);
    MOLDE.cr4.store(cr4, Ordering::Relaxed);
    // SAFETY: o PAT existe em todo x86_64.
    let pat = unsafe { x86_64::registers::model_specific::Msr::new(IA32_PAT).read() };
    MOLDE.pat.store(pat, Ordering::Relaxed);
    if cr4 & CR4_OSXSAVE != 0 {
        let (baixo, alto): (u32, u32);
        // SAFETY: `xgetbv` existe quando OSXSAVE está ligado, que é a
        // condição deste ramo.
        unsafe {
            core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") baixo, out("edx") alto,
                options(nomem, nostack, preserves_flags));
        }
        MOLDE
            .xcr0
            .store(((alto as u64) << 32) | baixo as u64, Ordering::Relaxed);
    }
}

/// Monta a raiz provisória: a do kernel, mais a identidade dos primeiros
/// 2 MiB na entrada zero.
///
/// Refeita a cada partida, e não uma vez só: a raiz do kernel pode ter
/// ganhado entradas de topo entre um núcleo e o próximo.
fn montar_raiz_provisoria(raiz_baixa: u64) -> Result<(), &'static str> {
    // A identidade usa dois frames: um diretório de 1 GiB e um de 2 MiB,
    // com uma página grande. Alocados uma vez, e mantidos: são reaproveitados
    // por todas as partidas.
    static IDENTIDADE: AtomicU64 = AtomicU64::new(0);
    let pdpt = match IDENTIDADE.load(Ordering::Acquire) {
        0 => {
            let pdpt = crate::frames::alocar().ok_or("sem frame para a identidade")?;
            let pd = crate::frames::alocar().ok_or("sem frame para a identidade")?;
            // SAFETY: os dois frames acabaram de sair do alocador e são
            // alcançáveis pelo mapa da memória física.
            unsafe {
                let pdpt_t = &mut *(paginacao::acesso_fisico(pdpt) as *mut PageTable);
                let pd_t = &mut *(paginacao::acesso_fisico(pd) as *mut PageTable);
                pdpt_t.zero();
                pd_t.zero();
                // Presente, gravável — sem o bit de usuário.
                *(&mut pdpt_t[0] as *mut _ as *mut u64) = pd | 0b11;
                // Presente, gravável, página grande (bit 7), endereço zero.
                *(&mut pd_t[0] as *mut _ as *mut u64) = 0b1000_0011;
            }
            IDENTIDADE.store(pdpt, Ordering::Release);
            pdpt
        }
        pdpt => pdpt,
    };

    let kernel = paginacao::espaco_do_kernel();
    // SAFETY: as duas raízes são frames de 4 KiB alcançáveis pelo mapa da
    // memória física. A baixa é nossa; a do kernel só é lida.
    unsafe {
        let destino = &mut *(paginacao::acesso_fisico(raiz_baixa) as *mut PageTable);
        let origem = &*(paginacao::acesso_fisico(kernel) as *const PageTable);
        for (i, entrada) in origem.iter().enumerate() {
            destino[i] = entrada.clone();
        }
        *(&mut destino[0] as *mut _ as *mut u64) = pdpt | 0b11;
    }
    Ok(())
}

/// Acorda o núcleo de APIC `hardware` como o núcleo `indice` do kernel, para
/// começar na pilha de topo `topo`.
pub fn partir(indice: usize, hardware: u64, topo: u64) -> Result<(), &'static str> {
    if !apic::pronto() {
        return Err("sem APIC local: nao ha como acordar outro nucleo");
    }
    let baixas = PAGINAS_BAIXAS.load(Ordering::Acquire);
    if baixas == 0 {
        return Err("sem pagina de partida abaixo de 1 MiB");
    }
    let hardware = u32::try_from(hardware).map_err(|_| "id de APIC grande demais")?;

    fotografar();
    let raiz_baixa = baixas + 4096;
    montar_raiz_provisoria(raiz_baixa)?;

    let tamanho = deslocamento(&raw const partida_fim) as usize;
    if tamanho > 4096 {
        return Err("o trampolim nao cabe numa pagina");
    }
    let destino = paginacao::acesso_fisico(baixas);
    // SAFETY: a página baixa foi reservada no boot e é só nossa; a origem é
    // o trampolim na imagem, com `tamanho` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(&raw const partida_inicio, destino, tamanho);

        let escrever_u32 = |rotulo: *const u8, valor: u32| {
            let em = destino.add(deslocamento(rotulo) as usize) as *mut u32;
            em.write_unaligned(valor);
        };
        let escrever_u64 = |rotulo: *const u8, valor: u64| {
            let em = destino.add(deslocamento(rotulo) as usize) as *mut u64;
            em.write_unaligned(valor);
        };

        // A base da GDT provisória e o destino do salto longo são endereços
        // lineares — dependem de onde a página está.
        escrever_u32(
            (&raw const partida_gdtr).add(2),
            (baixas + deslocamento(&raw const partida_gdt)) as u32,
        );
        escrever_u32(
            &raw const partida_salto,
            (baixas + deslocamento(&raw const partida_64)) as u32,
        );
        escrever_u64(&raw const partida_cr3, raiz_baixa);
        escrever_u64(&raw const partida_pilha, topo & !0xF);
        escrever_u64(&raw const partida_nucleo, indice as u64);
        let entrada: extern "sysv64" fn(u64) -> ! = entrada_secundaria;
        escrever_u64(&raw const partida_entrada, entrada as *const () as u64);
    }

    // SAFETY: a página tem o trampolim escrito, e o núcleo é um que o
    // firmware descreveu e ninguém acordou ainda — é o primeiro e único
    // sinal de partida que ele recebe.
    unsafe { apic::acordar(hardware, baixas) }
}

/// A primeira função Rust de um núcleo secundário.
///
/// Chega aqui pelo trampolim: modo longo, na raiz provisória, com a pilha do
/// fio ocioso e as interrupções desligadas. Nada mais do núcleo está
/// configurado — nem GDT de verdade, nem IDT, nem TSS.
extern "sysv64" fn entrada_secundaria(indice: u64) -> ! {
    use x86_64::registers::control::{Cr0, Cr4};
    let indice = indice as usize;

    // SAFETY: a raiz do kernel tem as mesmas entradas de topo da provisória
    // em toda a metade alta — onde estamos executando, com a pilha do ocioso
    // —, então trocar não muda nenhuma tradução em uso. Os registradores de
    // controle repetem os do primeiro núcleo, que é o regime em que todo o
    // kernel foi escrito para rodar.
    unsafe {
        paginacao::trocar_espaco(paginacao::espaco_do_kernel());
        Cr4::write_raw(MOLDE.cr4.load(Ordering::Relaxed));
        let xcr0 = MOLDE.xcr0.load(Ordering::Relaxed);
        if MOLDE.cr4.load(Ordering::Relaxed) & CR4_OSXSAVE != 0 && xcr0 != 0 {
            core::arch::asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32, options(nomem, nostack, preserves_flags));
        }
        Cr0::write_raw(MOLDE.cr0.load(Ordering::Relaxed));
        x86_64::registers::model_specific::Msr::new(IA32_PAT)
            .write(MOLDE.pat.load(Ordering::Relaxed));
        // O x87 num estado conhecido. O INIT não o deixa em estado
        // nenhum que se possa afirmar.
        core::arch::asm!("fninit", options(nomem, nostack));

        gdt::init_secundario(indice);
    }
    idt::carregar();

    // SAFETY: a GDT e o TSS deste núcleo acabaram de ser carregados.
    unsafe { usuario::ligar_neste_nucleo() };

    // SAFETY: estamos no núcleo que acabou de acordar, mascarado, com a IDT
    // carregada.
    if let Err(motivo) = unsafe { apic::ligar_neste_nucleo() } {
        crate::log_error!("smp", "o nucleo {} ficou sem timer: {}", indice, motivo);
    }

    crate::nucleos::entrar_secundario(indice)
}

// ---------------------------------------------------------------------------
// Os avisos por NMI
// ---------------------------------------------------------------------------

/// O endereço cuja tradução os outros núcleos precisam descartar.
static ALVO: AtomicU64 = AtomicU64::new(0);
/// Quem ainda não confirmou o descarte: um bit por núcleo.
static FALTAM: AtomicU8 = AtomicU8::new(0);
/// Um pedido de descarte por vez.
static TRAVA_DO_DESCARTE: Mutex<()> = Mutex::new(());

/// O sistema parou, e todo núcleo que receber uma NMI deve parar também.
static PARANDO: AtomicBool = AtomicBool::new(false);
/// Quem já parou: um bit por núcleo.
static PARADOS: AtomicU8 = AtomicU8::new(0);

/// Quantas vezes um núcleo esperou outro confirmar, no total.
static DESCARTES: AtomicU64 = AtomicU64::new(0);

/// Quantos descartes de tradução foram pedidos aos outros núcleos.
pub fn descartes() -> u64 {
    DESCARTES.load(Ordering::Relaxed)
}

/// Faz todos os outros núcleos descartarem a tradução de `virtual_`.
///
/// Chamada por quem acabou de desmapear uma página do **kernel**, com a
/// trava da paginação na mão e as interrupções mascaradas, **antes** de
/// devolver o frame ao alocador — um frame devolvido com uma tradução viva
/// em outro núcleo é memória de alguém que ainda pode ser escrita por quem
/// já a largou.
pub fn descartar_nos_outros(virtual_: u64) {
    if PARANDO.load(Ordering::Acquire) {
        // Os outros estão parados para sempre: não vão usar tradução
        // nenhuma, e esperar por eles seria esperar para sempre.
        return;
    }
    let eu = gdt::nucleo_atual();
    let outros = crate::nucleos::mascara_dos_ligados() & !(1u8 << eu);
    if outros == 0 {
        return;
    }

    crate::arch::sem_interrupcoes(|| {
        let _vez = TRAVA_DO_DESCARTE.lock();
        ALVO.store(virtual_, Ordering::Release);
        FALTAM.store(outros, Ordering::Release);
        DESCARTES.fetch_add(1, Ordering::Relaxed);

        avisar(outros);

        // # Por que não desistir de quem demora
        //
        // A versão anterior desistia depois de um teto de voltas: dava o
        // núcleo como perdido, tirava-o da conta dos ligados e seguia — e
        // quem chamou devolvia o frame ao alocador. A premissa era que um
        // núcleo que não responde a uma NMI não está rodando código nenhum.
        // Ela não vale para um núcleo **lento**: no emulador, uma CPU virtual
        // pode ficar sem a CPU do hospedeiro por um bom tempo. Ele voltava,
        // seguia rodando fios, e com a tradução velha na TLB escrevia num
        // frame que já era de outro — e, fora da conta dos ligados, não
        // recebia mais descarte nenhum.
        //
        // Um núcleo travado de verdade, girando com as interrupções
        // mascaradas, **responde**: a NMI atravessa a máscara (ver o caso
        // "smp: nucleo travado nao para os outros"). Então esperar não custa
        // o sistema por causa de um núcleo travado; custa só por um núcleo
        // que nem a NMI alcança, e com ele a coerência da memória já não se
        // pode prometer. A espera reenvia a NMI de tempos em tempos — um
        // aviso pode se perder — e, passado um prazo muito maior que o de
        // qualquer resposta, o sistema para pelo caminho da falha fatal, que
        // diz quem não respondeu. Parar é honesto; seguir era corromper.
        const VOLTAS: u64 = 200_000_000;
        const AVISOS: u32 = 16;
        for _ in 0..AVISOS {
            for _ in 0..VOLTAS {
                if FALTAM.load(Ordering::Acquire) == 0 || PARANDO.load(Ordering::Acquire) {
                    return;
                }
                core::hint::spin_loop();
            }
            REAVISOS.fetch_add(1, Ordering::Relaxed);
            avisar(FALTAM.load(Ordering::Acquire));
        }
        panic!(
            "os nucleos {:#010b} nao confirmaram o descarte da traducao {:#x}",
            FALTAM.load(Ordering::Acquire),
            virtual_
        );
    });
}

/// Manda a NMI de descarte a cada núcleo da máscara.
fn avisar(mascara: u8) {
    for i in 0..MAX_NUCLEOS {
        if mascara & (1 << i) == 0 {
            continue;
        }
        if let Some(h) = crate::nucleos::hardware(i).and_then(|h| u32::try_from(h).ok()) {
            // Uma recusa do APIC — o comando anterior ainda pendente — é
            // tratada como um aviso que se perdeu: a espera reenvia.
            let _ = apic::enviar_nmi(h);
        }
    }
}

/// Quantas vezes um descarte precisou reenviar o aviso a quem demorava.
static REAVISOS: AtomicU64 = AtomicU64::new(0);

/// Quantos avisos de descarte foram reenviados — ver `descartar_nos_outros`.
pub fn reavisos() -> u64 {
    REAVISOS.load(Ordering::Relaxed)
}

/// Para todos os outros núcleos, para sempre. Chamada pelo caminho de falha.
///
/// Devolve a máscara dos que confirmaram. Os que não confirmaram no prazo
/// não estão executando código do kernel — nem uma NMI os alcança —, e o
/// relatório segue sem eles.
pub fn parar_os_outros() -> u8 {
    PARANDO.store(true, Ordering::Release);
    let eu = gdt::nucleo_atual();
    let outros = crate::nucleos::mascara_dos_ligados() & !(1u8 << eu);
    for i in 0..MAX_NUCLEOS {
        if outros & (1 << i) != 0
            && let Some(h) = crate::nucleos::hardware(i).and_then(|h| u32::try_from(h).ok())
        {
            let _ = apic::enviar_nmi(h);
        }
    }
    const VOLTAS: u64 = 100_000_000;
    for _ in 0..VOLTAS {
        if PARADOS.load(Ordering::Acquire) & outros == outros {
            break;
        }
        core::hint::spin_loop();
    }
    PARADOS.load(Ordering::Acquire)
}

/// O que um núcleo faz ao receber uma NMI.
///
/// Sem trava nenhuma: a NMI pode ter chegado com este núcleo segurando
/// qualquer uma, e tomar uma trava aqui seria esperar por si mesmo.
pub fn atender_nmi() {
    let eu = gdt::nucleo_atual();
    let bit = 1u8 << eu;

    if PARANDO.load(Ordering::Acquire) {
        PARADOS.fetch_or(bit, Ordering::AcqRel);
        // Nunca voltamos: sem `iretq`, o processador também não entrega
        // outra NMI, e este núcleo fica parado de vez.
        loop {
            x86_64::instructions::interrupts::disable();
            x86_64::instructions::hlt();
        }
    }

    if FALTAM.load(Ordering::Acquire) & bit != 0 {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new_truncate(
            ALVO.load(Ordering::Acquire),
        ));
        FALTAM.fetch_and(!bit, Ordering::AcqRel);
    }
}

/// Para este núcleo, para sempre.
pub fn parar_este_nucleo() -> ! {
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}
