//! A trava do kernel: exclusão mútua **justa** entre núcleos.
//!
//! # Por que não o `spin::Mutex`
//!
//! Este kernel usou o `spin::Mutex` desde o primeiro dia, e com um núcleo só
//! ele era perfeito: a trava era sempre tomada com as interrupções
//! mascaradas, e então ninguém disputava com ninguém — quem a pedia a
//! encontrava livre.
//!
//! Com vários núcleos ela passa a ser disputada de verdade, e o `spin::Mutex`
//! padrão é um *teste-e-troca*: todos os que esperam tentam ao mesmo tempo, e
//! ganha quem chegar primeiro **naquele instante**. Não há fila. Um núcleo
//! que solta a trava e a pede de novo logo em seguida — um laço que consulta
//! o anel de log, por exemplo — ganha quase sempre, porque a linha de cache
//! já está com ele. O outro núcleo espera indefinidamente: é inanição, e foi
//! medida assim nesta fase — um processo num núcleo secundário escrevendo uma
//! linha de log por evento, contra a suíte no primeiro consultando o mesmo
//! anel em laço, levava um quarto de segundo por linha.
//!
//! Esta trava é por **senha**, como a fila de uma padaria: quem chega tira o
//! próximo número, e espera o painel mostrar o seu. É FIFO por construção —
//! quem pediu primeiro é atendido primeiro, e ninguém espera mais do que a
//! fila na frente dele.
//!
//! # Por que não o `TicketMutex` do mesmo crate
//!
//! Por causa do caminho de falha fatal, que destrava à força **todas** as
//! travas do kernel antes de relatar — presas ou não, porque não há como
//! saber quais estavam presas pelo código que morreu. O `force_unlock` do
//! `TicketMutex` avança o painel em um; numa trava que estava livre, isso
//! põe o painel **à frente** da próxima senha, e a próxima pessoa a pedir
//! espera para sempre por um número que já passou. E numa trava presa com
//! fila, avançar um entrega a vez ao primeiro da fila — que pode ser um
//! núcleo que acabou de ser parado, e nunca vai usá-la nem soltá-la.
//!
//! O destravamento daqui é outro: ele **abandona a fila**. O painel vai para
//! a próxima senha que seria tirada — a trava fica livre, e todas as senhas
//! já tiradas ficam para trás, sem vez nunca mais. Num caminho de falha isso
//! é exatamente o certo: quem estava na fila foi parado e não volta, e se
//! algum núcleo não parou — no ARM, um núcleo mascarado não ouve o aviso de
//! parada —, a senha dele ficou para trás e ele nunca entra na trava junto
//! com o relatório. Com o teste-e-troca, entrava.
//!
//! # A ordem entre travas
//!
//! Na suíte, cada trava tomada passa pela conferência da ordem
//! (`ordem_das_travas.rs`, só na suíte): duas travas tomadas nas duas ordens, em
//! qualquer lugar do kernel, reprovam a suíte.
//!
//! # A disciplina de uso não muda
//!
//! Toda trava continua sendo tomada com as interrupções mascaradas, pelo
//! mesmo motivo de sempre: um núcleo que segura uma trava (ou espera numa
//! fila) e é interrompido por um handler que pede a mesma trava espera por si
//! mesmo.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

/// Uma trava justa, por senha. A mesma forma de uso do `spin::Mutex`.
pub struct Mutex<T: ?Sized> {
    /// A próxima senha a ser tirada.
    proxima: AtomicU64,
    /// A senha que está sendo atendida.
    painel: AtomicU64,
    /// A classe desta trava na conferência da ordem, depois de conhecida.
    #[cfg(feature = "modo-teste")]
    classe: core::sync::atomic::AtomicU16,
    dado: UnsafeCell<T>,
}

// SAFETY: o dado só é alcançado por quem tem a vez — a exclusão é a da fila
// —, então compartilhar a trava entre núcleos é compartilhar o acesso
// exclusivo a `T`, o que exige só que `T` possa mudar de núcleo.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
// SAFETY: mover a trava move o dado.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

/// A vez na trava. Enquanto existir, o dado é de quem a tem.
pub struct Guarda<'a, T: ?Sized> {
    trava: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(dado: T) -> Self {
        Self {
            proxima: AtomicU64::new(0),
            painel: AtomicU64::new(0),
            #[cfg(feature = "modo-teste")]
            classe: core::sync::atomic::AtomicU16::new(u16::MAX),
            dado: UnsafeCell::new(dado),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// O nome da trava para a conferência da ordem: o endereço.
    #[cfg(feature = "modo-teste")]
    fn endereco(&self) -> usize {
        self as *const Self as *const u8 as usize
    }

    /// Tira uma senha e espera a vez.
    #[track_caller]
    pub fn lock(&self) -> Guarda<'_, T> {
        // Antes de esperar: uma ordem invertida é registrada mesmo quando o
        // impasse acontece de verdade, e não só quando não acontece.
        #[cfg(feature = "modo-teste")]
        crate::ordem_das_travas::ao_pedir(self.endereco(), &self.classe);
        // `Relaxed` basta para tirar a senha: o que ordena o acesso ao dado é
        // a leitura do painel, com `Acquire`, que casa com o `Release` de quem
        // soltou.
        let senha = self.proxima.fetch_add(1, Ordering::Relaxed);
        while self.painel.load(Ordering::Acquire) != senha {
            core::hint::spin_loop();
        }
        #[cfg(feature = "modo-teste")]
        crate::ordem_das_travas::ao_tomar(self.endereco(), &self.classe);
        Guarda { trava: self }
    }

    /// Pega a vez só se não houver ninguém com ela nem na fila.
    #[track_caller]
    pub fn try_lock(&self) -> Option<Guarda<'_, T>> {
        let painel = self.painel.load(Ordering::Acquire);
        let guarda = self
            .proxima
            .compare_exchange(painel, painel + 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Guarda { trava: self });
        // Sem espera, sem aresta: só a pilha de quem tem a trava na mão.
        #[cfg(feature = "modo-teste")]
        if guarda.is_some() {
            crate::ordem_das_travas::ao_tomar(self.endereco(), &self.classe);
        }
        guarda
    }

    /// Alguém tem a vez, ou está na fila?
    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.proxima.load(Ordering::Relaxed) != self.painel.load(Ordering::Relaxed)
    }

    /// Libera a trava à força, **abandonando a fila** — ver o topo do módulo.
    ///
    /// # Safety
    ///
    /// Só no caminho de falha fatal, com os outros núcleos parados: quem
    /// tinha a vez nunca mais a solta, e quem estava na fila nunca mais é
    /// atendido. Fora desse caminho, isso entregaria o dado a dois ao mesmo
    /// tempo.
    pub unsafe fn force_unlock(&self) {
        self.painel
            .store(self.proxima.load(Ordering::Acquire), Ordering::Release);
    }
}

impl<T: ?Sized> Deref for Guarda<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: a guarda existe só enquanto quem a tem tem a vez.
        unsafe { &*self.trava.dado.get() }
    }
}

impl<T: ?Sized> DerefMut for Guarda<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, e a guarda é única.
        unsafe { &mut *self.trava.dado.get() }
    }
}

impl<T: ?Sized> Drop for Guarda<'_, T> {
    fn drop(&mut self) {
        // A próxima senha é atendida. Somar, e não escrever "a minha mais
        // um": depois de um destravamento de emergência não há guarda velha
        // viva para soltar — quem a tinha foi parado —, e somar é o que
        // mantém a conta certa no caso normal.
        #[cfg(feature = "modo-teste")]
        crate::ordem_das_travas::ao_soltar(&self.trava.classe);
        self.trava.painel.fetch_add(1, Ordering::Release);
    }
}
