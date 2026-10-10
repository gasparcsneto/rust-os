//! O tecido nativo de segurança no kernel: o fio do NSF, as leituras e os
//! pedidos — tudo pelo gate.
//!
//! As contas moram no pacote `seguranca` (o modelo de evento, o grafo, as
//! regras, o incidente, o cofre, a resposta); o desenho e os contratos, em
//! `docs/SEGURANCA.md`. Este módulo faz só o que o pacote não pode:
//!
//! - põe o fio `nsf`, o único que fala como o serviço — com
//!   `Autoridade::Servico(Servico::Nsf)` e o papel que a linha `servico` da
//!   política dá a ela;
//! - a cada volta, **lê pelo gate**: `audit.tail` depois do último registro
//!   lido, e `net.observe` sobre cada servidor de DNS que o motor quer
//!   observar — com o papel do NSF, e gravado na auditoria como qualquer
//!   leitura;
//! - entrega ao motor o que leu, pega os pedidos que ele planejou, **pede
//!   cada um ao gate** e devolve o desfecho — uma recusa é o fim daquele
//!   objetivo: nada aqui tenta outro caminho;
//! - responde às consultas `security.*` com o estado do motor.
//!
//! # O que vem de fora do gate
//!
//! Dois números: o do último registro da auditoria
//! ([`crate::autorizacao::ultimo_registro`]) e o do último datagrama da
//! captura ([`crate::rede::captura::ultimo`]). São despertadores — dizem
//! que há o que ler, e não o quê —, e é o que deixa a auditoria quieta
//! quando nada acontece: o NSF só lê quando a cabeça passou da última
//! leitura dele. O `xtask` confere que este módulo não chama mais nada da
//! autorização, nem da captura, por fora do gate.
//!
//! # A cadência
//!
//! Uma volta por [`INTERVALO_MS`], no máximo, e só quando há o que ler.
//! Uma leitura recusada — o papel sem `audit.read`, a política sem a linha
//! `servico`, a taxa do papel — dobra a espera até [`ESPERA_MAXIMA_MS`]: o
//! NSF não insiste, e a recusa fica gravada uma vez por espera.
//!
//! # A trava
//!
//! [`MOTOR`], tomada com as interrupções mascaradas, como as outras, e por
//! pouco tempo: o JSON é lido fora dela, e ela nunca está na mão quando o
//! fio pede ao gate — o gate grava, e a gravação não espera o NSF.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use politica::sigiloso::Texto;
use protocolo::json::{Json, JsonWriter};
use seguranca::Motor;

use crate::autorizacao::{Autoridade, Chamador, Programa, Servico};
use crate::trava::Mutex;

/// O estado do NSF: o motor do pacote `seguranca`.
static MOTOR: Mutex<Option<Motor>> = Mutex::new(None);

/// O último registro que o motor leu — para o despertador olhar sem a
/// trava.
static LIDO: AtomicU64 = AtomicU64::new(0);

/// O último datagrama da captura que o fio viu ao ler.
static CAPTURA_VISTA: AtomicU64 = AtomicU64::new(0);

/// Antes de quando a próxima volta não acontece.
static PROXIMA_MS: AtomicU64 = AtomicU64::new(0);

/// A espera depois de uma recusa; zero sem recusa.
static ESPERA_MS: AtomicU64 = AtomicU64::new(0);

/// O intervalo mínimo entre duas voltas.
pub const INTERVALO_MS: u64 = 1_000;

/// A maior espera depois de recusas seguidas.
pub const ESPERA_MAXIMA_MS: u64 = 60_000;

/// Quantos registros cada `audit.tail` traz.
const LOTE: u64 = 64;

/// Quantos `audit.tail` uma volta faz, no máximo.
const LEITURAS_POR_VOLTA: usize = 8;

/// Quantos datagramas cada `net.observe` traz.
const DATAGRAMAS: u64 = 16;

/// O que uma volta fez.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Volta {
    /// Leituras pedidas ao gate, e quantas ele recusou.
    pub leituras: usize,
    pub recusadas: usize,
    /// Registros e datagramas novos.
    pub registros: usize,
    pub datagramas: usize,
    /// Pedidos de resposta feitos ao gate.
    pub pedidos: usize,
}

fn com_motor<R>(f: impl FnOnce(&mut Motor) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| MOTOR.lock().as_mut().map(f))
}

/// Liga o NSF: o motor, com o que já está na auditoria como história, e o
/// fio que o faz andar. No boot, depois da persistência — a janela que o
/// journal repôs é a história que o motor refaz.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn iniciar() {
    let agora = crate::autorizacao::ultimo_registro();
    crate::arch::sem_interrupcoes(|| {
        let mut m = Motor::novo();
        m.ao_vivo_depois_de(agora);
        *MOTOR.lock() = Some(m);
    });
    match crate::fios::criar_como("nsf", laco, 0, Autoridade::Servico(Servico::Nsf)) {
        Ok(id) => crate::log_info!("nsf", "tecido de seguranca no fio {}", id.numero()),
        Err(motivo) => crate::log_error!("nsf", "o fio do NSF nao subiu: {}", motivo),
    }
}

/// O fio do NSF: anda quando há o que ler, e descansa.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        if deve_andar(crate::tempo::uptime_ms()) {
            passo();
        }
        crate::fios::descansar_ate_a_interrupcao();
    }
}

/// Há o que ler, e passou o intervalo — ou a espera de uma recusa.
fn deve_andar(agora: u64) -> bool {
    agora >= PROXIMA_MS.load(Ordering::Acquire)
        && (crate::autorizacao::ultimo_registro() > LIDO.load(Ordering::Acquire)
            || crate::rede::captura::ultimo() > CAPTURA_VISTA.load(Ordering::Acquire))
}

/// O NSF, como o gate o vê: um pedido pelo fio que pede, com a autoridade
/// do serviço — e só ela —, e nenhuma imagem a atenuar.
fn chamador() -> Chamador {
    Chamador::Processo {
        fio: crate::fios::id_atual(),
        autoridade: Autoridade::Servico(Servico::Nsf),
        programa: Programa::Kernel,
    }
}

/// Pede um comando ao gate, como o NSF. `Ok` com o resultado; `Err` com o
/// envelope inteiro da recusa.
fn pedir(metodo: &str, params: &str) -> Result<Vec<u8>, Texto> {
    let mut linha = String::new();
    {
        let mut w = JsonWriter::new(&mut linha);
        let _ = w.begin_object();
        let _ = w.field_str("jsonrpc", "2.0");
        let _ = w.field_u64("id", 1);
        let _ = w.field_str("method", metodo);
        let _ = w.key("params");
        let _ = w.raw_value(params);
        let _ = w.end_object();
    }
    let envelope = crate::nativo::responder_pelo_kernel(chamador(), linha.as_bytes());
    match Json(envelope.como_bytes()).member("result") {
        Some(r) => Ok(r.0.to_vec()),
        None => Err(envelope),
    }
}

/// Uma recusa de leitura: a espera dobra, até o teto.
fn recuar(agora: u64) {
    let espera = (ESPERA_MS.load(Ordering::Acquire) * 2).clamp(INTERVALO_MS, ESPERA_MAXIMA_MS);
    ESPERA_MS.store(espera, Ordering::Release);
    PROXIMA_MS.store(agora + espera, Ordering::Release);
}

/// Uma volta do NSF: a auditoria, a captura, os pedidos. Só o fio do NSF e
/// a suíte chamam — o `xtask` confere.
pub fn passo() -> Volta {
    let agora = crate::tempo::uptime_ms();
    let mut volta = Volta::default();
    let mut recusou = false;
    if com_motor(|_| ()).is_none() {
        return volta;
    }
    // O custo da volta, para `security.metrics`: o tempo dela, dos pedidos
    // ao gate inclusive, e os registros que ela leu.
    let inicio = crate::arch::ciclos();

    // Os dois despertadores antes de ler: todo datagrama já contado em
    // `captura` é de uma associação que o gate abriu antes, num registro
    // até `cabeca`.
    let captura = crate::rede::captura::ultimo();
    let cabeca = crate::autorizacao::ultimo_registro();
    // A cabeça, para a saúde: um registro lido muito atrás dela é evidência
    // velha, e o NSF não contém sozinho por ela — ver `seguranca::motor`.
    com_motor(|m| m.cabeca_da_auditoria(cabeca));

    // A auditoria, até alcançar a cabeça — ou o teto da volta.
    for _ in 0..LEITURAS_POR_VOLTA {
        let lido = LIDO.load(Ordering::Acquire);
        if crate::autorizacao::ultimo_registro() <= lido {
            break;
        }
        let params = alloc::format!(r#"{{"after":{lido},"count":{LOTE}}}"#);
        volta.leituras += 1;
        match pedir("audit.tail", &params) {
            Ok(r) => {
                let registros = seguranca::evento::registros(&r).unwrap_or_default();
                let (novos, ate) =
                    com_motor(|m| (m.ler_registros(registros), m.lido())).unwrap_or((0, lido));
                LIDO.fetch_max(ate, Ordering::AcqRel);
                volta.registros += novos;
                if novos == 0 {
                    break;
                }
            }
            Err(_) => {
                volta.recusadas += 1;
                recusou = true;
                com_motor(|m| m.leitura_recusada());
                break;
            }
        }
    }

    // A captura depois: o servidor de DNS só entra em observação quando a
    // auditoria mostra alguém o usando — e um programa rápido resolve e
    // conecta antes de uma volta. O motor liga a resolução à conexão nas
    // duas ordens. Se a leitura da auditoria parou antes de `cabeca`, um
    // servidor ainda pode não ser conhecido: a captura fica como não
    // vista, e a volta seguinte lê de novo — cada servidor de onde parou.
    if captura > CAPTURA_VISTA.load(Ordering::Acquire) {
        for (destino, depois) in com_motor(|m| m.a_observar()).unwrap_or_default() {
            let params =
                alloc::format!(r#"{{"to":"{destino}","after":{depois},"max":{DATAGRAMAS}}}"#);
            volta.leituras += 1;
            match pedir("net.observe", &params) {
                Ok(r) => {
                    let lidos = seguranca::dns::capturas(&r).unwrap_or_default();
                    volta.datagramas += com_motor(|m| m.ler_capturas(&destino, lidos)).unwrap_or(0);
                }
                Err(_) => {
                    volta.recusadas += 1;
                    com_motor(|m| m.observacao_recusada(&destino));
                }
            }
        }
        if LIDO.load(Ordering::Acquire) >= cabeca {
            CAPTURA_VISTA.fetch_max(captura, Ordering::AcqRel);
        }
    }

    // Os pedidos que o motor planejou: cada um ao gate, e o desfecho de
    // volta. Uma recusa encerra o objetivo — é o motor que não planeja de
    // novo; daqui, nada tenta outro caminho.
    for p in com_motor(|m| m.pedidos()).unwrap_or_default() {
        volta.pedidos += 1;
        // A latência da resposta: do registro que disparou a detecção a
        // este pedido — se o registro ainda está no anel dos momentos.
        if let Some(gravado) = crate::metricas::momento_do_registro(p.origem) {
            crate::metricas::RESPOSTA_MS.somar(crate::tempo::uptime_ms().saturating_sub(gravado));
        }
        let envelope = match pedir(&p.metodo, &p.params) {
            Ok(resultado) => {
                let mut e = Vec::from(&br#"{"result":"#[..]);
                e.extend_from_slice(&resultado);
                e.push(b'}');
                e
            }
            Err(recusa) => recusa.como_bytes().to_vec(),
        };
        com_motor(|m| m.desfecho(p.acao, &envelope));
    }

    if recusou {
        recuar(agora);
    } else {
        ESPERA_MS.store(0, Ordering::Release);
        PROXIMA_MS.store(agora + INTERVALO_MS, Ordering::Release);
    }
    crate::metricas::VOLTA_DO_NSF.somar(crate::metricas::desde(inicio));
    crate::metricas::REGISTROS_DO_NSF.somar(volta.registros as u64);
    volta
}

/// Responde a uma consulta `security.*`: escreve com o motor travado num
/// texto, e o texto vai ao canal depois — a escrita no canal não é lugar de
/// segurar a trava.
pub fn consultar(
    f: impl FnOnce(&Motor, &mut JsonWriter) -> core::fmt::Result,
) -> Result<String, &'static str> {
    com_motor(|m| {
        let mut texto = String::new();
        let mut w = JsonWriter::new(&mut texto);
        let _ = f(m, &mut w);
        texto
    })
    .ok_or("o tecido de seguranca nao esta no ar")
}

/// Só para a suíte: o NSF começa agora — do registro de agora em diante,
/// sem história e sem espera —, e sem fio: o caso faz cada volta.
#[cfg(feature = "modo-teste")]
pub fn reiniciar_de_teste() {
    let agora = crate::autorizacao::ultimo_registro();
    let captura = crate::rede::captura::ultimo();
    crate::arch::sem_interrupcoes(|| {
        let mut m = Motor::novo();
        m.comecar_depois_de(agora, captura);
        *MOTOR.lock() = Some(m);
    });
    LIDO.store(agora, Ordering::Release);
    CAPTURA_VISTA.store(0, Ordering::Release);
    PROXIMA_MS.store(0, Ordering::Release);
    ESPERA_MS.store(0, Ordering::Release);
}

/// Só para a suíte: desliga o NSF — o caso seguinte não o tem.
#[cfg(feature = "modo-teste")]
pub fn desligar_de_teste() {
    crate::arch::sem_interrupcoes(|| *MOTOR.lock() = None);
}

/// Só para a suíte: lê o motor.
#[cfg(feature = "modo-teste")]
pub fn com_motor_de_teste<R>(f: impl FnOnce(&Motor) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| MOTOR.lock().as_ref().map(f))
}

/// Só para a suíte: a espera que uma recusa deixou.
#[cfg(feature = "modo-teste")]
pub fn espera_de_teste() -> u64 {
    ESPERA_MS.load(Ordering::Acquire)
}

/// Destrava o motor, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        MOTOR.force_unlock();
    }
}
