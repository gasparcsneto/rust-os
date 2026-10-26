//! A marca da imagem: o que o boot leu de `/etc/duke/imagem` — de onde veio o
//! disco desta máquina. O formato, e o porquê, são de `sigilo::imagem`.
//!
//! # O que o kernel faz com ela
//!
//! Mostra. No log do boot — um aviso, numa imagem de desenvolvimento ou sem
//! marca — e no `system.info`, para quem opera a máquina saber se diante
//! dele está uma de produção ou uma de bancada, com chaves cujas privadas
//! estão no `target/` de quem compilou.
//!
//! E nada mais: nenhuma decisão a lê — a conferência das invariantes do
//! `xtask` exige que só o `system.info` a alcance. Quem pode o quê continua
//! sendo a política, sobre as identidades dos registros; uma marca trocada
//! no disco não dá nem tira autoridade de ninguém.

use sigilo::imagem::{Marca, Tipo};

use crate::trava::Mutex;

/// Onde está.
pub const CAMINHO: &str = "/etc/duke/imagem";

/// O que o boot achou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Ainda não lida: o boot não chegou lá.
    NaoLida,
    /// Sem o arquivo: uma imagem de antes da marca, ou montada à mão.
    SemMarca,
    /// O arquivo, lido.
    Marcada(Marca),
    /// O arquivo não se leu: a linha (zero para o arquivo inteiro) e o
    /// motivo.
    Ilegivel(usize, &'static str),
}

static ESTADO: Mutex<Estado> = Mutex::new(Estado::NaoLida);

/// No boot, com a raiz montada: lê a marca e diz no log de onde veio a
/// imagem.
pub fn carregar() {
    let estado = ler();
    match &estado {
        Estado::Marcada(m) if m.tipo == Tipo::Producao => {
            crate::log_info!("imagem", "imagem de producao `{}` ({})", m.nome, Id(&m.id))
        }
        Estado::Marcada(m) => crate::log_warn!(
            "imagem",
            "imagem de DESENVOLVIMENTO `{}` ({}): as chaves, a politica e a pessoa sao as da bancada; nao e uma maquina de producao",
            m.nome,
            Id(&m.id)
        ),
        Estado::SemMarca => crate::log_warn!(
            "imagem",
            "a imagem nao tem marca ({}): nao se sabe se e de producao",
            CAMINHO
        ),
        Estado::Ilegivel(linha, motivo) => crate::log_error!(
            "imagem",
            "{}, linha {}: {}; nao se sabe se e de producao",
            CAMINHO,
            linha,
            motivo
        ),
        Estado::NaoLida => {}
    }
    crate::arch::sem_interrupcoes(|| *ESTADO.lock() = estado);
}

/// A marca, como o boot a deixou.
pub fn estado() -> Estado {
    crate::arch::sem_interrupcoes(|| ESTADO.lock().clone())
}

/// O arquivo, se ele existe e veio da imagem.
fn ler() -> Estado {
    match crate::vfs::ler_tudo_com_origem(CAMINHO) {
        Err(crate::vfs::Erro::NaoEncontrado) => Estado::SemMarca,
        Err(_) => Estado::Ilegivel(0, "o arquivo da marca nao se le"),
        // Só a imagem escreve a marca: o que alguém gravasse num caminho
        // alcançável não diria de onde veio o disco.
        Ok((_, origem)) if origem != crate::vfs::Origem::Imagem => {
            Estado::Ilegivel(0, "a marca nao veio da imagem")
        }
        Ok((bytes, _)) => match core::str::from_utf8(&bytes)
            .map_err(|_| (0, "a marca nao e texto"))
            .and_then(sigilo::imagem::ler)
        {
            Ok(m) => Estado::Marcada(m),
            Err((linha, motivo)) => Estado::Ilegivel(linha, motivo),
        },
    }
}

/// Destrava a marca à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ESTADO.force_unlock() };
}

/// O id, em hexadecimal, para o log e o `system.info`.
pub struct Id<'a>(pub &'a [u8; 16]);

impl core::fmt::Display for Id<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
