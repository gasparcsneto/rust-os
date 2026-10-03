//! Quedas de energia em pontos exatos, só na compilação da bancada.
//!
//! # Para que serve
//!
//! A bancada de persistência corta a energia com `SIGKILL`, e um corte no
//! instante certo — entre a descarga do disco e o avanço do contador do
//! TPM, digamos — é questão de sorte: a janela tem milissegundos. Esta
//! compilação põe a sorte de lado. Ela lê um plano no último setor da
//! partição de estado — em que ponto, e em que gravação desde o boot —, e
//! quando chega lá avisa pelo canal do agente e congela a máquina. A
//! bancada vê o aviso e corta a energia: o disco e o TPM ficam exatamente
//! como estavam naquele ponto.
//!
//! # Por que só ali
//!
//! O módulo só existe com a feature `quedas`, que só a bancada pede — o
//! `cargo xtask invariantes` confere. Num kernel de produção não há plano a
//! ler, nem ponto em que congelar.
//!
//! # O plano
//!
//! ```text
//!   0  "DUKEQUED"   a magia
//!   8  ponto  u8    ver [`Ponto`]
//!   9  reservado
//!  12  gravação u32 LE   a n-ésima gravação desde o boot (1 é a primeira),
//!                        para os pontos de dentro de uma gravação
//! ```

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

/// A magia do setor do plano.
const MAGIA: [u8; 8] = *b"DUKEQUED";

/// Onde a energia pode cair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ponto {
    /// O contador da âncora definido no TPM, e nunca avançado.
    AncoraDefinida = 1,
    /// O contador avançado uma vez, e o nascimento ainda não guardado.
    AncoraAvancada = 2,
    /// O nascimento guardado, e a abertura ainda não gravada.
    NascimentoGuardado = 3,
    /// Uma gravação montada, e nada escrito.
    AntesDaEscrita = 10,
    /// O registro escrito, e não descarregado.
    DepoisDaEscrita = 11,
    /// O registro descarregado, e o contador ainda não avançado.
    DepoisDaDescarga = 12,
    /// O contador avançado, e a gravação ainda não confirmada — nem a
    /// operação respondida.
    DepoisDoContador = 13,
}

static PONTO: AtomicU8 = AtomicU8::new(0);
static GRAVACAO: AtomicU32 = AtomicU32::new(0);
static GRAVACOES: AtomicU32 = AtomicU32::new(0);

/// Lê o plano do último setor da partição de estado, se houver um.
pub fn carregar<M: diario::Meio>(meio: &mut M) {
    let total = meio.setores();
    if total == 0 {
        return;
    }
    let mut setor = [0u8; 512];
    if meio.ler(total - 1, &mut setor).is_err() || setor[..8] != MAGIA {
        return;
    }
    let gravacao = u32::from_le_bytes([setor[12], setor[13], setor[14], setor[15]]);
    PONTO.store(setor[8], Ordering::Relaxed);
    GRAVACAO.store(gravacao, Ordering::Relaxed);
    crate::log_warn!(
        "quedas",
        "plano da bancada: a energia cai no ponto {} da gravacao {}",
        setor[8],
        gravacao
    );
}

/// Uma gravação começou: conta, para os pontos de dentro dela.
pub fn gravacao_comecou() {
    GRAVACOES.fetch_add(1, Ordering::Relaxed);
}

/// Se o plano manda a energia cair aqui, ela cai: o aviso sai pelo canal
/// do agente, e a máquina congela com as interrupções desligadas. Nada
/// mais roda — nenhum outro fio, nenhuma escrita, nenhuma resposta.
pub fn aqui(p: Ponto) {
    if PONTO.load(Ordering::Relaxed) != p as u8 {
        return;
    }
    let de_gravacao = p as u8 >= Ponto::AntesDaEscrita as u8;
    if de_gravacao && GRAVACOES.load(Ordering::Relaxed) != GRAVACAO.load(Ordering::Relaxed) {
        return;
    }
    crate::arch::sem_interrupcoes(|| {
        if let Some(mut guarda) = crate::serial::AGENT_LINK.try_lock()
            && let Some(porta) = guarda.as_mut()
        {
            let mut aviso = *b"\n{\"queda\":000}\n";
            let n = p as u8;
            aviso[10] = b'0' + n / 100;
            aviso[11] = b'0' + n / 10 % 10;
            aviso[12] = b'0' + n % 10;
            porta.write_bytes(&aviso);
        }
        loop {
            crate::arch::esperar_interrupcao();
        }
    })
}
