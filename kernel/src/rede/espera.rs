//! A espera de um `net.recv` ou de um `net.send`: o pedido que dorme até a
//! pilha ter o que dizer.
//!
//! # O evento
//!
//! Cada sentido tem o seu ([`Sentido`]). O socket do `smoltcp` guarda o
//! waker de quem espera a **leitura** e o aciona quando um dado entra no
//! buffer de recepção, quando o estado muda, e quando a conexão é fechada ou
//! derrubada (`close`, `abort`) — no TCP; no UDP, quando chega um
//! datagrama, de qualquer origem: o de outra que não o destino sai na mesma
//! volta da pilha, a conferência não acha nada, e a espera continua. E
//! guarda, à parte, o waker de quem espera **espaço para mandar**, e o
//! aciona quando um ACK do outro lado tira bytes da fila de saída — no TCP;
//! no UDP, quando um datagrama sai da fila —, e quando o estado muda. Quem
//! acorda é a pilha, na volta em que processou o evento — no fio `rede` ou
//! no comando que a sondou —, e quem espera não pergunta nada enquanto
//! isso. O prazo é o do relógio das tarefas ([`crate::tarefas::relogio`]),
//! acordado pelo tique.
//!
//! # O comando não espera: suspende
//!
//! Um handler roda no executor, e um handler que esperasse prenderia todos
//! os canais, os consoles e os processos atrás dele. O `net.recv` que não
//! tem o que dizer — e o `net.send` que não tem onde pôr nada — **arma** a
//! espera na conexão e **suspende** — ver
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
//! O `net.send` que suspende é executado de novo com o mesmo anexo: quem
//! despachou o guarda junto com a linha — o processo, no texto do pedido; o
//! canal, ao lado da linha suspensa —, e a entrega dos bytes também é
//! decidida de novo.
//!
//! # A espera pela auditoria
//!
//! O mesmo mecanismo serve a outra espera, que não é da conexão: a do
//! pedido do plano de dados que o gate adiou porque o caminho da auditoria
//! não tem lugar agora — ver [`crate::oleoduto`]. Ela é armada pelo gate,
//! e não pelo comando: o pedido não foi decidido, nem gravado, nem
//! executado. O despachante a guarda e a confere como guarda e confere a da
//! conexão, e acordado — o journal gravou, o NSF leu, ou o prazo do `wait`
//! venceu — executa o pedido de novo, inteiro, pelo gate.
//!
//! # A espera de quem recebe pela malha
//!
//! E serve à espera de um `fabric.recv` sem o que ler: armada no endpoint
//! da malha, ela acaba quando uma entrega chega a ele, quando ele fecha, ou
//! no prazo — ver [`crate::malha`]. A conferência e o registro do waker
//! acontecem sob a trava da tabela, a mesma com que a entrega entra. Uma
//! espera por endpoint: a segunda é recusada, como numa conexão.
//!
//! # A espera pela resposta de outro dispositivo
//!
//! E serve à espera de um pedido da malha a outro dispositivo: armada no
//! pedido da tabela do enlace, ela acaba quando o par responde, quando o
//! pedido falha — a revogação, a suspensão, o prazo —, ou no prazo da
//! espera — ver [`crate::enlace`]. Acordado, o pedido é executado de novo,
//! inteiro, pelo gate, e só então lê a resposta.
//!
//! # Uma espera de cada sentido por conexão
//!
//! Uma conexão tem um dono, e o dono pede uma coisa de cada vez pelo caminho
//! dele. Mas um agente pode pedir pelo canal e pelo Terminal em que confirma
//! uma linha, com o mesmo dono — e o socket guarda **um** waker de cada
//! sentido: o segundo apagaria o primeiro, que passaria a acordar só no
//! prazo, sem ninguém saber por quê. A segunda espera do mesmo sentido na
//! mesma conexão é recusada, com o motivo; uma leitura e um envio esperam
//! juntos, cada um no seu waker.

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

/// Para que lado a espera olha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sentido {
    /// A de um `net.recv`: o dado que chega.
    Leitura,
    /// A de um `net.send`: o espaço na fila de saída.
    Escrita,
}

/// Por que a espera acabou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// Chegou dado — a espera de leitura.
    Chegou,
    /// Abriu espaço na fila de saída — a espera de escrita.
    Coube,
    /// O estado mudou do que o pedido viu: o aperto terminou, o outro lado
    /// fechou, a conexão caiu.
    Mudou,
    /// A conexão não existe mais para o dono: ele a fechou por outro
    /// caminho, ela foi derrubada porque o dono acabou, ou uma regra do
    /// firewall a cortou — e então o pedido executado de novo ouve a regra.
    Sumiu,
    /// O prazo venceu sem nada disso.
    Venceu,
    /// O caminho da auditoria tem lugar de novo — a espera de um pedido
    /// que o gate adiou.
    Liberou,
}

/// Uma espera: armada numa conexão, ou pelo caminho da auditoria. Largá-la
/// a desarma.
#[derive(Debug)]
pub struct Espera {
    causa: Causa,
    /// O tique em que a espera vence.
    prazo: u64,
}

/// Pelo que se espera.
#[derive(Debug)]
enum Causa {
    /// O evento de uma conexão.
    Conexao {
        /// O número que a conexão guarda enquanto esta espera está armada.
        numero: u64,
        conexao: u64,
        dono: Dono,
        sentido: Sentido,
        /// O estado que o pedido viu: sair dele é um evento.
        estado: Estado,
    },
    /// Lugar no caminho da auditoria, para um pedido de dados de
    /// `principal` que o gate adiou.
    Auditoria {
        principal: crate::autorizacao::Principal,
        /// Desde quando, em milissegundos: a conta das esperas.
        desde_ms: u64,
    },
    /// Uma entrega no endpoint `endpoint` da malha — a espera de um
    /// `fabric.recv`.
    Malha { endpoint: u64 },
    /// A resposta do par ao pedido `pedido` do enlace — a espera de um
    /// pedido da malha a outro dispositivo. Ver [`crate::enlace`].
    Enlace { pedido: u64 },
}

/// O tique em que vence uma espera de `ms` milissegundos — no máximo
/// [`PRAZO_MAXIMO_MS`]. `None` sem relógio, que é quem venceria o prazo.
fn prazo_de(ms: u64) -> Option<u64> {
    let hz = crate::tempo::frequencia_hz() as u64;
    if hz == 0 {
        return None;
    }
    let tiques = ms
        .min(PRAZO_MAXIMO_MS)
        .saturating_mul(hz)
        .div_ceil(1000)
        .max(1);
    Some(crate::tempo::ticks().saturating_add(tiques))
}

impl Espera {
    /// Arma a espera de um `net.recv` — ou, no sentido da escrita, de um
    /// `net.send` — na conexão `conexao` de `dono`, por `ms` milissegundos
    /// — no máximo [`PRAZO_MAXIMO_MS`].
    ///
    /// `Ok(None)` quando não há o que esperar: já chegou dado, ou já cabe
    /// algo na fila de saída, ou a conexão está num estado de que nada mais
    /// vem — e sem relógio, que é quem venceria o prazo. `Err` com o motivo
    /// quando a conexão já tem quem espere naquele sentido, ou não é de
    /// `dono`.
    pub fn armar(
        conexao: u64,
        dono: Dono,
        ms: u64,
        sentido: Sentido,
    ) -> Result<Option<Espera>, &'static str> {
        let Some(prazo) = prazo_de(ms) else {
            return Ok(None);
        };
        Ok(
            pilha::armar(conexao, &dono, sentido)?.map(|(numero, estado)| Espera {
                causa: Causa::Conexao {
                    numero,
                    conexao,
                    dono,
                    sentido,
                    estado,
                },
                prazo,
            }),
        )
    }

    /// A espera de um pedido de dados de `principal` que o gate adiou: até
    /// o caminho da auditoria ter lugar para ele, por `ms` milissegundos —
    /// o `wait` do pedido, no máximo [`PRAZO_MAXIMO_MS`]. `None` sem
    /// relógio: sem prazo, não se adia. Só o gate arma — o `xtask` confere.
    pub fn pela_auditoria(principal: crate::autorizacao::Principal, ms: u64) -> Option<Espera> {
        Some(Espera {
            causa: Causa::Auditoria {
                principal,
                desde_ms: crate::tempo::uptime_ms(),
            },
            prazo: prazo_de(ms)?,
        })
    }

    /// A espera de um `fabric.recv` no endpoint `endpoint`, por `ms`
    /// milissegundos — no máximo [`PRAZO_MAXIMO_MS`]. `Ok(None)` quando não
    /// há o que esperar — já há o que ler, ou o endpoint acabou — e sem
    /// relógio; `Err` com o motivo quando o endpoint já tem quem espere.
    pub fn pela_malha(endpoint: u64, ms: u64) -> Result<Option<Espera>, &'static str> {
        let Some(prazo) = prazo_de(ms) else {
            return Ok(None);
        };
        if !crate::malha::armar_espera(endpoint)? {
            return Ok(None);
        }
        Ok(Some(Espera {
            causa: Causa::Malha { endpoint },
            prazo,
        }))
    }

    /// A espera pela resposta do par ao pedido `pedido` do enlace, por `ms`
    /// milissegundos — no máximo [`PRAZO_MAXIMO_MS`]. `None` quando não há o
    /// que esperar — ele terminou, ou saiu — e sem relógio.
    pub fn pelo_enlace(pedido: u64, ms: u64) -> Option<Espera> {
        let prazo = prazo_de(ms)?;
        if !crate::enlace::armar_espera(pedido) {
            return None;
        }
        Some(Espera {
            causa: Causa::Enlace { pedido },
            prazo,
        })
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
        match &self.causa {
            Causa::Conexao {
                numero,
                conexao,
                dono,
                sentido,
                estado,
            } => pilha::conferir_espera(*conexao, dono, *numero, *estado, *sentido, waker),
            Causa::Auditoria { principal, .. } => {
                crate::oleoduto::conferir(*principal, waker).then_some(Desfecho::Liberou)
            }
            Causa::Malha { endpoint } => crate::malha::conferir_espera(*endpoint, waker),
            Causa::Enlace { pedido } => crate::enlace::conferir_espera(*pedido, waker),
        }
        .or_else(|| (crate::tempo::ticks() >= self.prazo).then_some(Desfecho::Venceu))
    }
}

impl Drop for Espera {
    /// Desarma: a conexão volta a aceitar uma espera. A espera pela
    /// auditoria não tem o que desarmar — o waker guardado acorda à toa,
    /// no máximo —, e entra na conta das esperas.
    fn drop(&mut self) {
        match &self.causa {
            Causa::Conexao {
                numero,
                conexao,
                dono,
                ..
            } => pilha::desarmar(*conexao, dono, *numero),
            Causa::Auditoria { desde_ms, .. } => {
                crate::oleoduto::esperou(crate::tempo::uptime_ms().saturating_sub(*desde_ms))
            }
            Causa::Malha { endpoint } => crate::malha::desarmar_espera(*endpoint),
            Causa::Enlace { pedido } => crate::enlace::desarmar_espera(*pedido),
        }
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
