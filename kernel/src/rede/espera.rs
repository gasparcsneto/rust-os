//! A espera de um `net.recv`: o pedido que dorme até a pilha ter o que
//! dizer.
//!
//! # O evento
//!
//! O socket do `smoltcp` guarda o waker de quem espera a leitura e o
//! aciona quando um dado entra no buffer de recepção, quando o estado muda,
//! e quando a conexão é fechada ou derrubada (`close`, `abort`) — no TCP; no
//! UDP, quando chega um datagrama, de qualquer origem: o de outra que não o
//! destino sai na mesma volta da pilha, a conferência não acha nada, e a
//! espera continua. Quem acorda é a pilha, na volta em que processou o
//! evento — no fio `rede` ou no comando que a sondou —, e quem espera não
//! pergunta nada enquanto isso. O prazo é o do relógio das tarefas
//! ([`crate::tarefas::relogio`]), acordado pelo tique.
//!
//! # O comando não espera: suspende
//!
//! Um handler roda no executor, e um handler que esperasse prenderia todos
//! os canais, os consoles e os processos atrás dele. O `net.recv` que não
//! tem o que dizer **arma** a espera na conexão e **suspende** — ver
//! [`crate::autorizacao::suspender`] —, sem escrever resposta nenhuma. Quem
//! despachou o pedido é quem sabe esperar sem prender os outros:
//!
//! - a tarefa da sessão do canal, que só atende aquele agente;
//! - a tarefa `programas`, que guarda os pedidos suspensos dos processos e
//!   continua atendendo os outros — o fio do processo segue esperando a
//!   resposta, estacionado, como em qualquer pedido;
//! - o interpretador, que guarda o suspenso de cada console e continua
//!   atendendo os outros consoles e as janelas.
//!
//! Acordado, o despachante **executa o pedido de novo**, inteiro: a mesma
//! linha, o mesmo gate, uma decisão nova — com a política, o registro e a
//! sessão de agora —, gravada na auditoria. É ela que entrega o dado. A
//! decisão de antes da espera não vale para depois dela, como a de um
//! pedido não vale para o seguinte: uma revogação no meio da espera recusa
//! a entrega.
//!
//! # Uma espera por conexão
//!
//! Uma conexão tem um dono, e o dono pede uma coisa de cada vez pelo caminho
//! dele. Mas um agente pode pedir pelo canal e pelo Terminal em que confirma
//! uma linha, com o mesmo dono — e o socket guarda **um** waker: o segundo
//! apagaria o primeiro, que passaria a acordar só no prazo, sem ninguém
//! saber por quê. A segunda espera na mesma conexão é recusada, com o
//! motivo.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::conexoes::Dono;
use super::pilha::{self, Estado};
use crate::tarefas::relogio::{self, Dormir};

/// O maior prazo de uma espera, em milissegundos: o teto do `wait`.
///
/// Dez segundos: o tempo que os clientes da bancada já esperam uma
/// resposta, e o que um canal de agente fica sem atender outro pedido dele.
/// Quem quer esperar mais pede de novo — e a decisão é tomada de novo.
pub const PRAZO_MAXIMO_MS: u64 = 10_000;

/// Por que a espera acabou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// Chegou dado.
    Chegou,
    /// O estado mudou do que o pedido viu: o aperto terminou, o outro lado
    /// fechou, a conexão caiu.
    Mudou,
    /// A conexão não existe mais para o dono: ele a fechou por outro
    /// caminho, ou ela foi derrubada porque o dono acabou.
    Sumiu,
    /// O prazo venceu sem nada disso.
    Venceu,
}

/// Uma espera armada numa conexão. Largá-la a desarma.
#[derive(Debug)]
pub struct Espera {
    /// O número que a conexão guarda enquanto esta espera está armada.
    numero: u64,
    conexao: u64,
    dono: Dono,
    /// O estado que o pedido viu: sair dele é um evento.
    estado: Estado,
    /// O tique em que a espera vence.
    prazo: u64,
}

impl Espera {
    /// Arma a espera de um `net.recv` na conexão `conexao` de `dono`, por
    /// `ms` milissegundos — no máximo [`PRAZO_MAXIMO_MS`].
    ///
    /// `Ok(None)` quando não há o que esperar: já chegou dado, ou a conexão
    /// está num estado de que nada mais vem — e sem relógio, que é quem
    /// venceria o prazo. `Err` com o motivo quando a conexão já tem quem
    /// espere, ou não é de `dono`.
    pub fn armar(conexao: u64, dono: Dono, ms: u64) -> Result<Option<Espera>, &'static str> {
        let hz = crate::tempo::frequencia_hz() as u64;
        if hz == 0 {
            return Ok(None);
        }
        let tiques = ms
            .min(PRAZO_MAXIMO_MS)
            .saturating_mul(hz)
            .div_ceil(1000)
            .max(1);
        let prazo = crate::tempo::ticks().saturating_add(tiques);
        Ok(
            pilha::armar(conexao, &dono)?.map(|(numero, estado)| Espera {
                numero,
                conexao,
                dono,
                estado,
                prazo,
            }),
        )
    }

    /// O tique em que a espera vence.
    pub fn prazo(&self) -> u64 {
        self.prazo
    }

    /// A espera acabou? `None` se ainda não — e então `waker`, se veio um,
    /// fica no socket para o próximo evento da conexão. Quem só confere,
    /// sem esperar, passa `None`: um waker que não acorda ninguém apagaria
    /// o de quem espera.
    ///
    /// A conferência e o registro acontecem sob a trava da pilha, a mesma
    /// com que ela processa o que chega: um evento cai antes — e a
    /// conferência o vê — ou depois — e acorda o waker registrado.
    pub fn conferir(&self, waker: Option<&Waker>) -> Option<Desfecho> {
        pilha::conferir_espera(self.conexao, &self.dono, self.numero, self.estado, waker)
            .or_else(|| (crate::tempo::ticks() >= self.prazo).then_some(Desfecho::Venceu))
    }
}

impl Drop for Espera {
    /// Desarma: a conexão volta a aceitar uma espera.
    fn drop(&mut self) {
        pilha::desarmar(self.conexao, &self.dono, self.numero);
    }
}

/// O desfecho de uma espera, para quem espera por ela sozinho — a tarefa de
/// uma sessão do canal: acorda pelo evento da conexão ou pelo tique do
/// prazo, e não pergunta nada entre um e outro.
pub struct Aguardar<'a> {
    espera: &'a Espera,
    relogio: Dormir,
}

impl<'a> Aguardar<'a> {
    pub fn nova(espera: &'a Espera) -> Aguardar<'a> {
        Aguardar {
            espera,
            relogio: relogio::ate_o_tique(espera.prazo),
        }
    }
}

impl Future for Aguardar<'_> {
    type Output = Desfecho;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Desfecho> {
        let este = self.get_mut();
        if let Some(d) = este.espera.conferir(Some(cx.waker())) {
            return Poll::Ready(d);
        }
        // O prazo: o relógio guarda o waker, e o tique o aciona.
        match Pin::new(&mut este.relogio).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Desfecho::Venceu),
            Poll::Pending => Poll::Pending,
        }
    }
}
