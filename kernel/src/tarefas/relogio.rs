//! [`Dormir`]: o futuro que espera o tempo passar.
//!
//! É a tarefa assíncrona mais simples que existe e, por isso, a melhor para
//! demonstrar o mecanismo: ela devolve `Pending`, guarda seu waker, e o
//! handler do timer a acorda. Nenhuma espera ativa em lugar nenhum.
//!
//! # O prazo mora junto com o waker
//!
//! A tabela guarda, para cada adormecido, o tique em que ele quer acordar. O
//! handler do timer compara e só aciona quem venceu.
//!
//! Guardar apenas os wakers e acordar todos a cada tique também funcionaria —
//! acordar cedo demais é sempre seguro, é o que o contrato de `poll` chama de
//! despertar espúrio. Mas a diferença é grande na prática: uma tarefa que
//! dorme um minuto seria repollada seis mil vezes em vez de uma. Comparar dois
//! inteiros dentro do handler é barato demais para abrir mão disso.
//!
//! O que continua simplificado é a *estrutura*: uma varredura linear por uma
//! tabela pequena, e não uma fila de prioridade. Com dezenas de adormecidos a
//! varredura passa a pesar, e aí a fila ordenada vale a troca.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use spin::Mutex;

/// Quantas tarefas podem esperar tempo ao mesmo tempo.
const MAX_DORMENTES: usize = 16;

/// Uma espera registrada: quando acordar, e quem acordar.
struct Espera {
    alvo: u64,
    waker: Waker,
}

/// Tarefas que esperam o relógio.
///
/// Protegida pela mesma disciplina do resto do kernel: quem toca nesta tabela
/// o faz com as interrupções mascaradas, e é isso que torna seguro escrevê-la
/// de dentro do handler do timer.
static DORMENTES: Mutex<[Option<Espera>; MAX_DORMENTES]> =
    Mutex::new([const { None }; MAX_DORMENTES]);

/// Espera até que o contador de tiques alcance `alvo`.
pub struct Dormir {
    alvo: u64,
    /// Vaga ocupada na tabela de dormentes, quando há uma.
    vaga: Option<usize>,
}

/// Dorme por `ticks` interrupções do timer.
pub fn por_ticks(ticks: u64) -> Dormir {
    Dormir {
        alvo: crate::tempo::ticks().saturating_add(ticks),
        vaga: None,
    }
}

/// Dorme por aproximadamente `ms` milissegundos.
///
/// A resolução é a do timer: a 100 Hz, um tique são 10 ms, e qualquer espera
/// é arredondada para cima até o próximo tique. Dormir zero tiques seria
/// devolver `Ready` na hora, então garantimos ao menos um.
pub fn por_ms(ms: u64) -> Dormir {
    let hz = crate::tempo::frequencia_hz() as u64;
    let ticks = if hz == 0 {
        // Sem timer não há como medir tempo. Um tique nominal faz a tarefa
        // ceder uma vez em vez de girar, que é o comportamento menos ruim.
        1
    } else {
        ms.saturating_mul(hz).div_ceil(1000).max(1)
    };
    por_ticks(ticks)
}

impl Dormir {
    /// Guarda o waker numa vaga, reaproveitando a que já tivermos.
    ///
    /// Devolve `false` quando a tabela está cheia.
    fn registrar(&mut self, waker: &Waker) -> bool {
        let alvo = self.alvo;
        crate::arch::sem_interrupcoes(|| {
            let mut tabela = DORMENTES.lock();

            let vaga = match self.vaga {
                Some(vaga) => vaga,
                None => match tabela.iter().position(|e| e.is_none()) {
                    Some(vaga) => {
                        self.vaga = Some(vaga);
                        vaga
                    }
                    None => return false,
                },
            };

            // `will_wake` evita clonar de novo o mesmo waker a cada repolagem
            // — e, principalmente, evita destruir o anterior aqui, o que
            // poderia devolver memória ao heap em ponto arbitrário.
            match &mut tabela[vaga] {
                Some(espera) if espera.waker.will_wake(waker) => espera.alvo = alvo,
                vaga => {
                    *vaga = Some(Espera {
                        alvo,
                        waker: waker.clone(),
                    })
                }
            }
            true
        })
    }

    fn liberar(&mut self) {
        if let Some(vaga) = self.vaga.take() {
            crate::arch::sem_interrupcoes(|| DORMENTES.lock()[vaga] = None);
        }
    }
}

impl Future for Dormir {
    type Output = ();

    fn poll(self: Pin<&mut Self>, contexto: &mut Context) -> Poll<()> {
        // `Dormir` só guarda números: não há autorreferência possível, então
        // sair do `Pin` é seguro e o próprio compilador o permite via `Unpin`.
        let este = self.get_mut();

        if crate::tempo::ticks() >= este.alvo {
            este.liberar();
            return Poll::Ready(());
        }

        if !este.registrar(contexto.waker()) {
            // Tabela cheia. Devolver `Pending` sem waker registrado seria
            // dormir para sempre — a tarefa nunca mais seria acordada. Pedir
            // para ser acordado imediatamente degrada para espera ativa, que é
            // desperdício mas mantém o progresso garantido.
            crate::log_warn!("tarefa", "tabela de dormentes cheia; caindo em polling");
            contexto.waker().wake_by_ref();
            return Poll::Pending;
        }

        // Reconferimos depois de registrar. Se o tique caiu entre a primeira
        // checagem e o registro, este segundo teste o encontra; sem ele, o
        // aviso se perderia na fresta e a tarefa dormiria um ciclo inteiro a
        // mais — ou para sempre, se não houvesse mais tiques.
        if crate::tempo::ticks() >= este.alvo {
            este.liberar();
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Dormir {
    /// Devolve a vaga quando a espera acaba ou é cancelada.
    ///
    /// Sem isto, uma tarefa encerrada deixaria seu waker na tabela para
    /// sempre: as vagas se esgotariam e, pior, o timer passaria a acordar
    /// tarefas que não existem mais a cada tique.
    fn drop(&mut self) {
        self.liberar();
    }
}

/// Acorda quem já venceu o prazo. Chamado do handler do timer.
pub fn tique() {
    let agora = crate::tempo::ticks();

    crate::arch::sem_interrupcoes(|| {
        let tabela = DORMENTES.lock();
        for espera in tabela.iter().flatten() {
            if espera.alvo <= agora {
                // `wake_by_ref` e não `wake`: acordar por referência não mexe
                // na contagem do `Arc`, então nenhuma liberação de memória
                // pode acontecer aqui dentro do handler. A vaga em si é
                // devolvida pela própria tarefa, ao repollar.
                espera.waker.wake_by_ref();
            }
        }
    });
}
