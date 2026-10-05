//! Vários núcleos: quantos a máquina tem, quais ligaram, e o pulso de cada um.
//!
//! # O que este módulo é, e o que ele não é
//!
//! Ele é a parte **neutra** de ligar núcleos: a tabela de quem existe, a
//! ordem em que eles são acordados, e o que um núcleo faz depois de acordar.
//! Como **descobrir** os núcleos e como **acordá-los** é de cada arquitetura,
//! e as duas não têm nada em comum:
//!
//! - no x86, a ACPI lista um APIC local por processador (a tabela MADT), e
//!   acordar é mandar a sequência INIT, SIPI, SIPI pelo APIC do núcleo que
//!   já está de pé — o núcleo novo acorda em **modo real**, de 16 bits, numa
//!   página abaixo de 1 MiB;
//! - no ARM, o device tree lista os núcleos em `/cpus`, e acordar é pedir ao
//!   firmware, pela interface PSCI, que ligue aquele núcleo num endereço
//!   nosso — ele acorda já em 64 bits, mas com a MMU desligada.
//!
//! Depois de acordado, todo núcleo faz o mesmo: adota o fio ocioso que foi
//! preparado para ele, diz que ligou, liga as interrupções e passa a ser um
//! lugar onde o escalonador pode pôr fios — ver [`entrar_secundario`].
//!
//! # O que fica no primeiro núcleo
//!
//! As interrupções dos dispositivos e o relógio do sistema. Os outros núcleos
//! têm timer próprio, e ele só serve para o escalonador deles: o relógio é
//! um só, e quem o anda é o primeiro. Com todos andando, ele andaria tantas
//! vezes mais rápido quantos fossem os núcleos.
//!
//! # Por que um pulso por núcleo
//!
//! Porque "o núcleo 2 travou" é uma pergunta que o canal do agente precisa
//! poder responder, e a única resposta que não depende do próprio núcleo
//! travado é olhar se o timer dele continua chegando. Cada núcleo conta os
//! próprios tiques; um núcleo cujo contador parou está com as interrupções
//! desligadas há esse tempo todo.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

/// Quantos núcleos o kernel acompanha.
///
/// Oito porque é o teto do controlador de interrupções do ARM desta máquina
/// — o GICv2 endereça no máximo oito interfaces de CPU — e porque um bitmap
/// de oito cabe num byte em toda máscara que o kernel precisar montar. Um
/// núcleo além do teto não é ligado, e o log diz quantos ficaram de fora.
pub const MAX_NUCLEOS: usize = 8;

/// Quanto o primeiro núcleo espera, em tiques do relógio, por um núcleo que
/// mandou acordar.
///
/// Cem tiques são um segundo a 100 Hz. Um núcleo de verdade liga em
/// microssegundos; o emulador, interpretando instrução por instrução, em
/// alguns milissegundos. Um segundo inteiro sem resposta não é lentidão, é
/// um núcleo que não vai ligar.
const ESPERA_EM_TIQUES: u64 = 100;

/// Em que pé está um núcleo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Estado {
    /// Não há núcleo nesta posição da tabela.
    Ausente = 0,
    /// O hardware o descreve, e ninguém tentou acordá-lo ainda.
    Descoberto = 1,
    /// O sinal de partida foi mandado, e ele ainda não respondeu.
    Partindo = 2,
    /// Acordou, adotou o fio ocioso e está recebendo fios.
    Ligado = 3,
    /// Não respondeu no prazo, ou o hardware recusou a partida.
    ///
    /// É um estado final: um núcleo que acordasse depois disso encontraria
    /// o fio ocioso dele já devolvido, e por isso [`entrar_secundario`] o
    /// manda parar em vez de prosseguir.
    Falhou = 4,
}

impl Estado {
    fn de(valor: u8) -> Estado {
        match valor {
            1 => Estado::Descoberto,
            2 => Estado::Partindo,
            3 => Estado::Ligado,
            4 => Estado::Falhou,
            _ => Estado::Ausente,
        }
    }

    /// O nome que o canal do agente mostra.
    pub fn nome(self) -> &'static str {
        match self {
            Estado::Ausente => "absent",
            Estado::Descoberto => "discovered",
            Estado::Partindo => "starting",
            Estado::Ligado => "online",
            Estado::Falhou => "failed",
        }
    }
}

/// Um núcleo, do ponto de vista do kernel.
///
/// Tudo atômico, e nada sob trava: quem lê esta tabela é, entre outros, o
/// canal do agente perguntando se um núcleo travou — e uma trava que o
/// núcleo travado estivesse segurando calaria justamente essa resposta.
struct Nucleo {
    estado: AtomicU8,
    /// Como o hardware o chama: o id do APIC local no x86, o `MPIDR` no ARM.
    hardware: AtomicU64,
    /// Quantos tiques do timer **deste** núcleo já chegaram.
    tiques: AtomicU64,
    /// A vaga do fio ocioso preparado para ele.
    ocioso: AtomicUsize,
}

static NUCLEOS: [Nucleo; MAX_NUCLEOS] = [const {
    Nucleo {
        estado: AtomicU8::new(Estado::Ausente as u8),
        hardware: AtomicU64::new(0),
        tiques: AtomicU64::new(0),
        ocioso: AtomicUsize::new(usize::MAX),
    }
}; MAX_NUCLEOS];

/// Quantos núcleos o hardware descreveu além do teto.
static DESCARTADOS: AtomicUsize = AtomicUsize::new(0);

/// Já houve uma rodada de partida? Uma só por boot.
static PARTIDA_FEITA: AtomicBool = AtomicBool::new(false);

/// Em que núcleo este código está rodando.
///
/// O número é a posição na tabela deste módulo, e não o id do hardware: o
/// primeiro núcleo é sempre o zero, e os outros seguem na ordem em que o
/// hardware os descreve. Ver [`crate::arch`] para como cada arquitetura
/// responde sem depender de nada que o processo controle.
pub fn atual() -> usize {
    crate::arch::nucleo_atual()
}

/// Conta um tique do timer deste núcleo. Chamado pelo handler do timer.
pub fn tique_local() {
    let n = atual();
    if n < MAX_NUCLEOS {
        NUCLEOS[n].tiques.fetch_add(1, Ordering::Relaxed);
    }
}

/// Este é o núcleo que anda o relógio e atende os dispositivos?
pub fn e_o_primeiro() -> bool {
    atual() == 0
}

/// Quantos núcleos estão ligados — o primeiro incluído.
pub fn ligados() -> usize {
    NUCLEOS
        .iter()
        .filter(|n| Estado::de(n.estado.load(Ordering::Acquire)) == Estado::Ligado)
        .count()
}

/// Os núcleos ligados, como máscara de bits: o bit `i` é o núcleo `i`.
pub fn mascara_dos_ligados() -> u8 {
    let mut mascara = 0u8;
    for (i, n) in NUCLEOS.iter().enumerate() {
        if Estado::de(n.estado.load(Ordering::Acquire)) == Estado::Ligado {
            mascara |= 1 << i;
        }
    }
    mascara
}

/// O id de hardware do núcleo `i`, se ele existe.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub fn hardware(i: usize) -> Option<u64> {
    let n = NUCLEOS.get(i)?;
    (Estado::de(n.estado.load(Ordering::Acquire)) != Estado::Ausente)
        .then(|| n.hardware.load(Ordering::Acquire))
}

/// Uma linha do relatório de núcleos.
#[derive(Clone, Copy, Debug)]
pub struct Retrato {
    pub indice: usize,
    pub estado: Estado,
    pub hardware: u64,
    pub tiques: u64,
}

/// Percorre a tabela, chamando `f` para cada núcleo que existe.
pub fn com_nucleos(mut f: impl FnMut(Retrato)) {
    for (indice, n) in NUCLEOS.iter().enumerate() {
        let estado = Estado::de(n.estado.load(Ordering::Acquire));
        if estado == Estado::Ausente {
            continue;
        }
        f(Retrato {
            indice,
            estado,
            hardware: n.hardware.load(Ordering::Acquire),
            tiques: n.tiques.load(Ordering::Relaxed),
        });
    }
}

/// Quem está conduzindo o fim do sistema — a falha fatal ou o pânico.
static DONO_DO_FIM: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Reivindica para este núcleo o caminho de falha, e para os outros.
///
/// # Por que alguém precisa ser o dono
///
/// Porque o caminho de falha destrava **à força** todas as travas do kernel
/// para conseguir relatar, e isso só é aceitável com um núcleo só rodando.
/// Dois núcleos falhando ao mesmo tempo destravariam um por cima do outro e
/// disputariam o canal do agente — e um terceiro, ainda rodando, entraria
/// nas travas recém-abertas junto com o relatório.
///
/// Então o primeiro a chegar é o dono, e manda os outros pararem; quem chega
/// depois — porque falhou também, ou porque recebeu o aviso — para sem dizer
/// nada. O mesmo núcleo pode chegar de novo (uma falha dentro do relatório),
/// e segue: ele já é o dono.
///
/// Quem não é o dono não volta.
pub fn reivindicar_o_fim() {
    let eu = atual();
    match DONO_DO_FIM.compare_exchange(usize::MAX, eu, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            let outros = mascara_dos_ligados() & !(1u8 << eu.min(MAX_NUCLEOS - 1));
            if outros != 0 {
                let parados = crate::arch::parar_os_outros();
                FIM_PARADOS.store(parados & outros, Ordering::Release);
                FIM_SEM_RESPOSTA.store(outros & !parados, Ordering::Release);
            }
        }
        Err(dono) if dono == eu => {}
        Err(_) => crate::arch::parar_este_nucleo(),
    }
}

/// Quais núcleos pararam a pedido do caminho de falha.
static FIM_PARADOS: AtomicU8 = AtomicU8::new(0);
/// Quais não confirmaram a parada no prazo.
static FIM_SEM_RESPOSTA: AtomicU8 = AtomicU8::new(0);

/// `(parados, sem resposta)`, como máscaras, do caminho de falha.
pub fn parada_do_fim() -> (u8, u8) {
    (
        FIM_PARADOS.load(Ordering::Acquire),
        FIM_SEM_RESPOSTA.load(Ordering::Acquire),
    )
}

/// Acorda os núcleos da máscara que estiverem dormindo, menos este.
///
/// # Para que
///
/// Um núcleo sem trabalho dorme até a próxima interrupção, e a próxima
/// costuma ser o timer dele: até dez milissegundos. Quando outro núcleo põe
/// trabalho para ele — um fio pronto, uma tarefa na fila do executor —, esse
/// é o atraso de começar. O cutucão é uma interrupção que não pede nada:
/// ela só tira o núcleo do sono, e o código dele confere o que mudou.
///
/// Perder um cutucão não é perder trabalho: o timer acordaria o núcleo do
/// mesmo jeito, um tique depois. É por isso que ele pode ser mandado sem
/// trava e sem confirmação.
pub fn cutucar(mascara: u8) {
    let eu = atual().min(MAX_NUCLEOS - 1);
    let alvo = mascara & mascara_dos_ligados() & !(1u8 << eu);
    if alvo != 0 {
        CUTUCOES.fetch_add(alvo.count_ones() as u64, Ordering::Relaxed);
        crate::arch::cutucar(alvo);
    }
}

/// O que um núcleo faz ao ser cutucado, além de acordar.
///
/// Chamada pelo handler do cutucão de cada arquitetura. Hoje, no primeiro
/// núcleo, é levar à tela o que outro núcleo compôs — ver
/// [`crate::grafico::apresentar_pendente`]. Nos outros, nada: acordar já é
/// tudo.
pub fn ao_ser_cutucado() {
    crate::grafico::apresentar_pendente();
}

/// Quantos cutucões foram mandados.
static CUTUCOES: AtomicU64 = AtomicU64::new(0);

/// Quantos cutucões foram mandados desde o boot.
pub fn cutucoes() -> u64 {
    CUTUCOES.load(Ordering::Relaxed)
}

/// Quantos núcleos o hardware descreveu e ficaram além do teto.
pub fn descartados() -> usize {
    DESCARTADOS.load(Ordering::Relaxed)
}

/// Registra o primeiro núcleo — este, que já está rodando.
///
/// Chamado cedo no boot, antes de qualquer outro núcleo existir. O primeiro
/// núcleo não é "descoberto": ele é quem descobre.
pub fn registrar_o_primeiro(hardware: u64) {
    NUCLEOS[0].hardware.store(hardware, Ordering::Release);
    NUCLEOS[0]
        .estado
        .store(Estado::Ligado as u8, Ordering::Release);
}

/// Acorda os demais núcleos, um de cada vez.
///
/// Chamado pelo primeiro núcleo, com o escalonador já no ar: cada núcleo que
/// acorda precisa de um fio ocioso para adotar, e é o escalonador que os
/// tem. Uma vez por boot.
///
/// # Por que um de cada vez
///
/// Porque no x86 todos acordam pela **mesma** página baixa, com a mesma
/// pilha de partida escrita nela. Acordar dois ao mesmo tempo os poria
/// lendo e escrevendo o mesmo bloco. Esperar cada um dizer que ligou antes
/// de mandar o próximo é o que torna a página reutilizável sem trava.
pub fn ligar_os_demais() {
    if PARTIDA_FEITA.swap(true, Ordering::AcqRel) {
        return;
    }

    let primeiro = NUCLEOS[0].hardware.load(Ordering::Acquire);
    let mut proximo = 1usize;
    crate::arch::descobrir_nucleos(|hardware| {
        if hardware == primeiro {
            return;
        }
        if proximo >= MAX_NUCLEOS {
            DESCARTADOS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        NUCLEOS[proximo].hardware.store(hardware, Ordering::Release);
        NUCLEOS[proximo]
            .estado
            .store(Estado::Descoberto as u8, Ordering::Release);
        proximo += 1;
    });

    let descobertos = proximo;
    crate::log_info!(
        "smp",
        "{} nucleo(s) descrito(s) pelo hardware{}",
        descobertos,
        if descartados() > 0 {
            " (alem do teto, alguns ficam desligados)"
        } else {
            ""
        }
    );
    if descartados() > 0 {
        crate::log_warn!(
            "smp",
            "{} nucleo(s) alem do teto de {} ficam desligados",
            descartados(),
            MAX_NUCLEOS
        );
    }

    for indice in 1..descobertos {
        if let Err(motivo) = ligar(indice) {
            crate::log_error!("smp", "o nucleo {} nao ligou: {}", indice, motivo);
        }
    }

    crate::log_info!(
        "smp",
        "{} de {} nucleo(s) ligado(s)",
        ligados(),
        descobertos
    );
}

/// Acorda o núcleo `indice` e espera ele dizer que ligou.
fn ligar(indice: usize) -> Result<(), &'static str> {
    let nucleo = &NUCLEOS[indice];
    let hardware = nucleo.hardware.load(Ordering::Acquire);

    let (vaga, topo) = crate::fios::preparar_ocioso(indice)?;
    nucleo.ocioso.store(vaga, Ordering::Release);
    nucleo
        .estado
        .store(Estado::Partindo as u8, Ordering::Release);

    if let Err(motivo) = crate::arch::partir_nucleo(indice, hardware, topo) {
        nucleo.estado.store(Estado::Falhou as u8, Ordering::Release);
        // SAFETY: a partida não foi enviada, ou foi recusada pelo firmware —
        // o núcleo não vai acordar sobre esta pilha.
        unsafe { crate::fios::desistir_do_ocioso(vaga) };
        return Err(motivo);
    }

    let comeco = crate::tempo::ticks();
    loop {
        match Estado::de(nucleo.estado.load(Ordering::Acquire)) {
            Estado::Ligado => break,
            Estado::Partindo => {}
            _ => return Err("o nucleo mudou de estado durante a partida"),
        }
        if crate::tempo::ticks().wrapping_sub(comeco) > ESPERA_EM_TIQUES {
            // Desistir é uma troca de estado **atômica**: se o núcleo ligar
            // exatamente agora, um dos dois perde a corrida, e quem perde
            // sabe. Ele, para não adotar uma pilha devolvida; nós, para não
            // devolver a pilha de um núcleo que acabou de adotá-la.
            if nucleo
                .estado
                .compare_exchange(
                    Estado::Partindo as u8,
                    Estado::Falhou as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // O ocioso **não** é devolvido. O núcleo pode estar no meio
                // do caminho — já sobre a pilha, ainda sem ter chegado à
                // troca de estado —, e devolver a pilha seria entregá-la a
                // outro fio debaixo dele. Uma vaga perdida por um núcleo
                // que não ligou é o preço de não ter essa corrida.
                return Err("nao respondeu no prazo");
            }
            continue;
        }
        crate::arch::esperar_interrupcao();
    }

    crate::log_info!(
        "smp",
        "nucleo {} ligado (hardware {:#x}), fio ocioso na vaga {}",
        indice,
        hardware,
        vaga
    );
    Ok(())
}

/// O que um núcleo secundário faz depois que a arquitetura o deixou de pé.
///
/// Chamada pelo código de partida de cada arquitetura, já na pilha do fio
/// ocioso, com as exceções instaladas, o timer local programado e as
/// interrupções ainda mascaradas. Nunca retorna: daqui em diante este núcleo
/// é o fio ocioso dele, e o escalonador o tira dali quando houver trabalho.
pub fn entrar_secundario(indice: usize) -> ! {
    let nucleo = &NUCLEOS[indice];

    // Primeiro reivindicar a partida, e só depois adotar o fio: se o
    // primeiro núcleo já desistiu de nós, o fio ocioso pode ter sido
    // devolvido, e adotá-lo seria assumir uma vaga que é de outro.
    if nucleo
        .estado
        .compare_exchange(
            Estado::Partindo as u8,
            Estado::Ligado as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // Tarde demais. Ficar parado é o único desfecho que não toca em
        // nada de ninguém.
        crate::arch::parar_este_nucleo();
    }

    crate::fios::adotar_ocioso(nucleo.ocioso.load(Ordering::Acquire));
    crate::arch::ligar_interrupcoes();
    ocioso()
}

/// O laço do fio ocioso: ceder a quem tiver trabalho, e dormir se ninguém
/// tiver.
///
/// Dorme com as interrupções ligadas. O timer deste núcleo o acorda a cada
/// tique, e é nesse acordar que ele confere se apareceu trabalho — a mesma
/// latência máxima de um tique que o coletor já tem.
fn ocioso() -> ! {
    loop {
        crate::fios::ceder();
        crate::arch::esperar_interrupcao();
    }
}

/// Até quando o núcleo travado de propósito fica travado, em tiques do
/// relógio; `u64::MAX` é para sempre.
static TRAVADO_ATE: AtomicU64 = AtomicU64::new(0);
/// Quantos fios de travamento estão girando agora.
static TRAVADOS: AtomicUsize = AtomicUsize::new(0);

/// O maior travamento com prazo que se pode pedir: dez minutos.
pub const MAIOR_TRAVAMENTO_MS: u64 = 600_000;

/// Trava o núcleo `indice` de propósito, com as interrupções desligadas,
/// por `ms` milissegundos — ou para sempre, com zero.
///
/// # Para que isto existe
///
/// Para provar, de fora, que um núcleo travado não leva o sistema junto: o
/// canal do agente continua respondendo, os outros núcleos continuam
/// escalonando, e o pulso do travado para — que é como se vê que ele
/// travou. É a falha que um kernel com vários núcleos precisa sobreviver, e
/// sem um jeito de provocá-la ela só seria vista quando acontecesse.
///
/// O travamento é o pior possível sem ser uma falha: interrupções
/// desligadas, girando, sem ceder. O timer daquele núcleo não chega, o
/// escalonador não o alcança, e nenhuma interrupção comum o tira dali.
///
/// # O que é recusado
///
/// O primeiro núcleo, porque é nele que o canal do agente, o relógio e os
/// dispositivos moram: travá-lo é derrubar o canal que está pedindo, e isso
/// não é um teste, é um desligamento. E um núcleo que não está ligado.
pub fn travar(indice: usize, ms: u64) -> Result<u64, &'static str> {
    if indice == 0 {
        return Err("o primeiro nucleo e o do canal e do relogio, e nao e travado por aqui");
    }
    let Some(n) = NUCLEOS.get(indice) else {
        return Err("nucleo alem do teto");
    };
    if Estado::de(n.estado.load(Ordering::Acquire)) != Estado::Ligado {
        return Err("o nucleo nao esta ligado");
    }
    if ms > MAIOR_TRAVAMENTO_MS {
        return Err("travamento com prazo acima do teto");
    }
    let ate = if ms == 0 {
        u64::MAX
    } else {
        let hz = crate::tempo::frequencia_hz().max(1) as u64;
        crate::tempo::ticks().saturating_add(ms.saturating_mul(hz).div_ceil(1000))
    };
    TRAVADO_ATE.store(ate, Ordering::Release);

    extern "C" fn girar(_argumento: u64) -> ! {
        TRAVADOS.fetch_add(1, Ordering::AcqRel);
        crate::arch::sem_interrupcoes(|| {
            while crate::tempo::ticks() < TRAVADO_ATE.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
        });
        TRAVADOS.fetch_sub(1, Ordering::AcqRel);
        crate::fios::terminar()
    }

    let id = crate::fios::criar_no_nucleo("travado", girar, 0, indice)?;
    crate::log_warn!(
        "smp",
        "nucleo {} travado de proposito{}",
        indice,
        if ms == 0 { ", para sempre" } else { "" }
    );
    Ok(id.numero())
}

/// Solta um travamento com prazo antes da hora — ou um eterno, que daqui
/// passa a ter fim. Existe para a suíte não deixar um núcleo preso para os
/// casos seguintes.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn soltar_travamento() {
    TRAVADO_ATE.store(0, Ordering::Release);
}

/// Quantos fios de travamento estão girando agora.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn travados() -> usize {
    TRAVADOS.load(Ordering::Acquire)
}
