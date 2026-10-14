//! O cliente: um pedido de cada vez numa conexão, e a mesma conexão para o
//! pedido seguinte quando a resposta deixa (*keep-alive*).
//!
//! Sem pedidos em fila (*pipelining*): o pedido seguinte só sai depois de a
//! resposta anterior ter sido lida inteira. E uma conexão que não pode
//! levar outro pedido — a resposta disse `Connection: close`, não tinha fim
//! certo, ou a troca falhou no meio — recusa o próximo
//! ([`Erro::Esgotada`]): quem chama abre outra, e a abertura é uma decisão
//! nova do gate.
//!
//! Com um pote ([`Cliente::trocar_com_pote`]), o pedido leva os cookies que
//! o pote dá para ele, e os `Set-Cookie` da resposta vão para o pote — e
//! saem dos cabeçalhos da resposta que quem chama vê. Ver
//! [`crate::cookies`].

use alloc::vec::Vec;

use crate::cookies::{Agora, Pote};
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

    /// Manda `pedido` e lê a resposta, com `limites`. Sem pote: o pedido
    /// não leva cookie, e a resposta traz os `Set-Cookie` como vieram.
    pub fn trocar(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
    ) -> Result<Resposta, Erro<F::Falha>> {
        self.trocar_com(pedido, limites, None)
    }

    /// Manda `pedido` com os cookies de `pote` e lê a resposta, com
    /// `limites`; os `Set-Cookie` dela vão para o pote, e saem dos
    /// cabeçalhos. `relogio` dá o tempo de agora, em segundos desde 1970 —
    /// lido só se um cookie com validade estiver em jogo, e uma vez. A
    /// troca que falha não grava cookie nenhum.
    pub fn trocar_com_pote(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        pote: &mut Pote,
        relogio: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<Resposta, Erro<F::Falha>> {
        let mut agora = Agora::de(relogio);
        let (cookie, retidos) =
            pote.cabecalho(&pedido.url, pedido.metodo, pedido.contexto, &mut agora);
        let mut r = self.trocar_com(pedido, limites, cookie.as_deref())?;
        r.cookies = pote.guardar(&pedido.url, pedido.contexto, &r.cabecalhos, &mut agora);
        r.cookies.retidos = retidos;
        r.cabecalhos.retain(|(nome, _)| nome != "set-cookie");
        Ok(r)
    }

    fn trocar_com(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        cookie: Option<&str>,
    ) -> Result<Resposta, Erro<F::Falha>> {
        if !self.pronto {
            return Err(Erro::Esgotada);
        }
        // Até a resposta chegar inteira, a conexão não leva outro pedido:
        // uma troca que falha no meio a deixa num ponto que ninguém sabe.
        self.pronto = false;
        self.fluxo
            .mandar(&pedido.escrever_com(cookie))
            .map_err(Erro::Baixo)?;
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
