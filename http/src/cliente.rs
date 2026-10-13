//! O cliente: um pedido de cada vez numa conexão, e a mesma conexão para o
//! pedido seguinte quando a resposta deixa (*keep-alive*).
//!
//! Sem pedidos em fila (*pipelining*): o pedido seguinte só sai depois de a
//! resposta anterior ter sido lida inteira. E uma conexão que não pode
//! levar outro pedido — a resposta disse `Connection: close`, não tinha fim
//! certo, ou a troca falhou no meio — recusa o próximo
//! ([`Erro::Esgotada`]): quem chama abre outra, e a abertura é uma decisão
//! nova do gate.

use alloc::vec::Vec;

use crate::erro::Erro;
use crate::pedido::Pedido;
use crate::resposta::{self, Limites, Resposta};

/// O lado de baixo: a conexão que leva os bytes.
///
/// Num programa do Duke, `net.send` e `net.recv` sobre a conexão que o
/// `net.connect` abriu — ou o TLS por cima dela —, cada pedido decidido
/// pelo gate. A falha é a de quem implementa: o HTTP a devolve em
/// [`Erro::Baixo`] como veio, sem traduzir.
pub trait Fluxo {
    /// A falha do transporte.
    type Falha;

    /// Manda `dados` inteiros, esperando espaço quando não há.
    fn mandar(&mut self, dados: &[u8]) -> Result<(), Self::Falha>;

    /// Recebe o que chegar, até `destino.len()` bytes, esperando por algo.
    /// `Ok(0)` só quando o outro lado fechou **limpo**: um fecho que pode
    /// ter cortado a conversa — o TLS sem `close_notify` — é uma falha, e
    /// não o fim.
    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Self::Falha>;
}

/// Uma conexão HTTP/1.1.
pub struct Cliente<F: Fluxo> {
    fluxo: F,
    /// O que chegou depois da última resposta.
    buffer: Vec<u8>,
    /// A conexão leva o pedido seguinte.
    pronto: bool,
    trocas: u64,
}

impl<F: Fluxo> Cliente<F> {
    pub fn novo(fluxo: F) -> Cliente<F> {
        Cliente {
            fluxo,
            buffer: Vec::new(),
            pronto: true,
            trocas: 0,
        }
    }

    /// A conexão leva o pedido seguinte.
    pub fn pronto(&self) -> bool {
        self.pronto
    }

    /// Quantas trocas terminaram com uma resposta nesta conexão.
    pub fn trocas(&self) -> u64 {
        self.trocas
    }

    /// Manda `pedido` e lê a resposta, com `limites`.
    pub fn trocar(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
    ) -> Result<Resposta, Erro<F::Falha>> {
        if !self.pronto {
            return Err(Erro::Esgotada);
        }
        // Até a resposta chegar inteira, a conexão não leva outro pedido:
        // uma troca que falha no meio a deixa num ponto que ninguém sabe.
        self.pronto = false;
        self.fluxo.mandar(&pedido.escrever()).map_err(Erro::Baixo)?;
        let mut r = resposta::ler(
            &mut self.fluxo,
            &mut self.buffer,
            pedido.metodo,
            pedido.aceitas,
            limites,
        )?;
        r.reutilizavel &= !pedido.fechar;
        self.pronto = r.reutilizavel;
        self.trocas += 1;
        Ok(r)
    }

    /// O transporte, para quem precisa dele entre as trocas.
    pub fn fluxo(&mut self) -> &mut F {
        &mut self.fluxo
    }

    /// Devolve o transporte, para quem chamou fechá-lo.
    pub fn devolver(self) -> F {
        self.fluxo
    }
}
