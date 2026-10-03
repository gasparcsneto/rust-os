//! O relógio de parede: o RTC da máquina.
//!
//! # Para que serve, e para que não serve
//!
//! O kernel sabe há quanto tempo está ligado — [`crate::tempo`] conta as
//! interrupções do timer. Isso não diz que horas são, e um boot o zera. Um
//! prazo que precisa sobreviver a um reboot — o de uma mensagem, o de um
//! desafio gravado — precisa de um relógio que continue andando com a
//! máquina desligada. É o RTC: o CMOS do PC, alimentado por bateria; a
//! PL031 da máquina `virt` do ARM.
//!
//! # Por que ele sozinho não basta
//!
//! Porque um RTC se acerta. Quem tem a máquina muda a data no firmware, a
//! bateria acaba e ele volta a 1970, o emulador sobe com a data que se
//! mandar — e é exatamente isso que a bancada de persistência faz. Um prazo
//! confiado ao RTC cru seria um prazo que qualquer um estica voltando o
//! relógio. Por isso este módulo só **lê**; o tempo lógico, que nunca volta,
//! é o RTC com um piso gravado no journal, e é o journal quem o mantém.

/// Segundos desde 1970-01-01 00:00:00 UTC para uma data do calendário
/// gregoriano, ou `None` para uma data que não existe ou antes de 1970.
///
/// O algoritmo é o dos dias desde a época civil de Howard Hinnant: conta os
/// dias desde 1º de março do ano zero, o que põe o 29 de fevereiro no fim
/// do "ano" e tira dele o caso especial.
#[cfg_attr(
    all(target_arch = "aarch64", not(feature = "modo-teste")),
    allow(
        dead_code,
        reason = "a PL031 ja diz segundos; a conversao e do CMOS do x86, e da suite"
    )
)]
pub fn segundos_desde_1970(
    ano: u32,
    mes: u32,
    dia: u32,
    hora: u32,
    minuto: u32,
    segundo: u32,
) -> Option<u64> {
    if !(1970..=9999).contains(&ano)
        || !(1..=12).contains(&mes)
        || dia == 0
        || dia > dias_no_mes(ano, mes)
        || hora > 23
        || minuto > 59
        || segundo > 59
    {
        return None;
    }
    let (a, m) = if mes <= 2 {
        (ano - 1, mes + 9)
    } else {
        (ano, mes - 3)
    };
    let era = a / 400;
    let ano_da_era = a - era * 400;
    let dia_do_ano = (153 * m + 2) / 5 + dia - 1;
    let dia_da_era = ano_da_era * 365 + ano_da_era / 4 - ano_da_era / 100 + dia_do_ano;
    let dias = era as u64 * 146_097 + dia_da_era as u64;
    // 719 468 é quantos dias há de 0000-03-01 até 1970-01-01.
    let dias = dias.checked_sub(719_468)?;
    Some(dias * 86_400 + hora as u64 * 3600 + minuto as u64 * 60 + segundo as u64)
}

#[cfg_attr(
    all(target_arch = "aarch64", not(feature = "modo-teste")),
    allow(
        dead_code,
        reason = "a PL031 ja diz segundos; a conversao e do CMOS do x86, e da suite"
    )
)]
fn dias_no_mes(ano: u32, mes: u32) -> u32 {
    match mes {
        2 if ano.is_multiple_of(4) && (!ano.is_multiple_of(100) || ano.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// O valor de um registrador do CMOS em BCD, como binário.
#[cfg_attr(
    all(target_arch = "aarch64", not(feature = "modo-teste")),
    allow(
        dead_code,
        reason = "a PL031 ja diz segundos; a conversao e do CMOS do x86, e da suite"
    )
)]
pub fn de_bcd(v: u8) -> u8 {
    (v >> 4) * 10 + (v & 0x0F)
}

/// Os segundos desde 1970 que o RTC diz, ou `None` se não há RTC ou ele
/// diz algo que não é uma data.
pub fn agora() -> Option<u64> {
    rtc::ler()
}

/// Prepara o acesso ao RTC.
pub fn init() {
    rtc::init();
    match agora() {
        Some(s) => crate::log_info!("relogio", "RTC: {} segundos desde 1970", s),
        None => crate::log_warn!("relogio", "nenhum RTC legivel nesta maquina"),
    }
}

#[cfg(target_arch = "x86_64")]
mod rtc {
    //! O RTC do PC: o relógio do chip CMOS, por duas portas de I/O.
    //!
    //! Escreve-se o número do registrador na porta `0x70` e lê-se o valor
    //! na `0x71`. Os valores vêm em BCD ou binário, em 12 ou 24 horas,
    //! conforme o registrador B — e o firmware é quem escolhe, então os dois
    //! são lidos.

    use x86_64::instructions::port::Port;

    const SEGUNDO: u8 = 0x00;
    const MINUTO: u8 = 0x02;
    const HORA: u8 = 0x04;
    const DIA: u8 = 0x07;
    const MES: u8 = 0x08;
    const ANO: u8 = 0x09;
    /// O século, onde o PC moderno o põe (o registrador que a tabela FADT
    /// da ACPI aponta; `0x32` no QEMU e na maioria das placas).
    const SECULO: u8 = 0x32;
    const ESTADO_A: u8 = 0x0A;
    const ESTADO_B: u8 = 0x0B;
    /// No registrador A: uma atualização está em curso, e os valores podem
    /// estar pela metade.
    const ATUALIZANDO: u8 = 1 << 7;
    /// No B: os valores são binários, e não BCD.
    const BINARIO: u8 = 1 << 2;
    /// No B: 24 horas.
    const VINTE_E_QUATRO_HORAS: u8 = 1 << 1;
    /// Na hora, em 12 horas: depois do meio-dia.
    const PM: u8 = 1 << 7;

    pub fn init() {}

    fn registrador(r: u8) -> u8 {
        // SAFETY: as portas 0x70 e 0x71 são as do CMOS em todo PC; ler um
        // registrador do relógio não tem efeito colateral. O bit 7 de 0x70
        // (que mascara a NMI) fica como o número o deixa: zero.
        unsafe {
            Port::<u8>::new(0x70).write(r);
            Port::<u8>::new(0x71).read()
        }
    }

    type Leitura = [u8; 7];

    fn uma_leitura() -> Leitura {
        // Espera a atualização acabar: lida no meio dela, a data pode ser
        // meio velha, meio nova — 23:59:59 com o dia seguinte.
        for _ in 0..1_000_000 {
            if registrador(ESTADO_A) & ATUALIZANDO == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        [
            registrador(SEGUNDO),
            registrador(MINUTO),
            registrador(HORA),
            registrador(DIA),
            registrador(MES),
            registrador(ANO),
            registrador(SECULO),
        ]
    }

    pub fn ler() -> Option<u64> {
        // Duas leituras iguais seguidas: a única garantia de que uma
        // atualização não começou entre a espera e a última leitura.
        let mut anterior = uma_leitura();
        let mut leitura = anterior;
        for _ in 0..10 {
            leitura = uma_leitura();
            if leitura == anterior {
                break;
            }
            anterior = leitura;
        }
        if leitura != anterior {
            return None;
        }
        let b = registrador(ESTADO_B);
        let [s, mi, h, d, me, a, c] = leitura;
        let pm = h & PM != 0;
        let conv = |v: u8| {
            if b & BINARIO != 0 {
                v
            } else {
                super::de_bcd(v)
            }
        };
        let mut hora = conv(h & !PM) as u32;
        if b & VINTE_E_QUATRO_HORAS == 0 {
            hora %= 12;
            if pm {
                hora += 12;
            }
        }
        let seculo = match conv(c) {
            0 => 20,
            s => s as u32,
        };
        super::segundos_desde_1970(
            seculo * 100 + conv(a) as u32,
            conv(me) as u32,
            conv(d) as u32,
            hora,
            conv(mi) as u32,
            conv(s) as u32,
        )
    }
}

#[cfg(target_arch = "aarch64")]
mod rtc {
    //! A PL031 da ARM: um contador de segundos desde 1970, num registrador.
    //!
    //! Mais simples que o CMOS: o registrador de dados (`RTCDR`, no
    //! deslocamento zero) já é o número que queremos. O endereço vem do
    //! device tree.

    use core::sync::atomic::{AtomicU64, Ordering};

    /// O endereço virtual do bloco, ou zero se não há.
    static BASE: AtomicU64 = AtomicU64::new(0);

    pub fn init() {
        // SAFETY: o ponteiro do device tree é o que o boot validou.
        let Some((fisico, _)) = (unsafe {
            crate::arch::aarch64::fdt::encontrar_mmio(crate::arch::aarch64::dtb(), b"arm,pl031")
        }) else {
            return;
        };
        match crate::mmio::mapear(fisico, 0x1000) {
            Ok(base) => BASE.store(base, Ordering::Release),
            Err(motivo) => crate::log_error!("relogio", "a PL031 nao foi mapeada: {}", motivo),
        }
    }

    pub fn ler() -> Option<u64> {
        let base = BASE.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        // SAFETY: `base` é o mapeamento de dispositivo da PL031, com uma
        // página; o `RTCDR` é o registrador de 32 bits no deslocamento zero.
        let segundos = unsafe { core::ptr::read_volatile(base as *const u32) };
        Some(segundos as u64)
    }
}
