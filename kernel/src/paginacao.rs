//! Fachada de paginação, neutra de arquitetura.
//!
//! # Por que esta camada existe
//!
//! [`crate::arch::mapear_frame`] é `unsafe`, e com razão: o chamador precisa
//! garantir que o frame não esteja em uso por nenhum outro mapeamento. Duas
//! páginas apontando para o mesmo frame são dois caminhos de escrita para a
//! mesma memória física — o equivalente a duas referências `&mut` para o mesmo
//! lugar, que é comportamento indefinido em Rust antes mesmo de ser um
//! problema de kernel.
//!
//! O erro fácil é envolver essa operação numa função segura e seguir em
//! frente. A função pareceria inofensiva e qualquer chamador poderia, sem
//! escrever `unsafe`, apontar uma página nova para memória que o kernel já
//! está usando.
//!
//! A saída adotada aqui é **satisfazer o invariante por construção**:
//! [`mapear_novo`] tira o frame do alocador, que por contrato só entrega
//! frames não usados. Com isso a condição perigosa deixa de depender da
//! disciplina do chamador, e a função pode ser segura de verdade.
//!
//! Quem precisa de um frame específico — registradores mapeados em memória,
//! por exemplo — continua usando a função `unsafe` e assume a
//! responsabilidade explicitamente.

use crate::arch::{self, Permissoes, TAMANHO_PAGINA};

/// Mapeia um endereço virtual sobre memória recém-alocada.
///
/// Devolve o endereço físico do frame, para que o chamador possa liberá-lo
/// depois — ou use [`desmapear_e_liberar`], que faz as duas coisas.
pub fn mapear_novo(virtual_: u64, permissoes: Permissoes) -> Result<u64, &'static str> {
    let frame = crate::frames::alocar().ok_or("memoria fisica esgotada")?;

    // Zerar não é higiene opcional. Um frame recém-alocado carrega o que quer
    // que estivesse ali antes, e entregar isso a um novo dono vaza dados do
    // dono anterior. Hoje só há o kernel e o vazamento é inócuo; quando houver
    // processos, seria uma falha de isolamento — e a hora de acertar é antes
    // de existir alguém para quem vazar.
    //
    // SAFETY: o frame acabou de sair do alocador, então somos seu único dono,
    // e `acesso_fisico` devolve o endereço virtual por onde o kernel o
    // enxerga.
    unsafe {
        core::ptr::write_bytes(arch::acesso_fisico(frame), 0, TAMANHO_PAGINA as usize);
    }

    // SAFETY: este é exatamente o invariante que a função exige — o frame veio
    // do alocador, que por contrato só entrega frames que não estão em uso.
    match unsafe { arch::mapear_frame(virtual_, frame, permissoes) } {
        Ok(()) => Ok(frame),
        Err(motivo) => {
            // Sem isto, um endereço virtual inválido custaria um frame a cada
            // tentativa — um vazamento controlado pelo chamador.
            crate::frames::liberar(frame);
            Err(motivo)
        }
    }
}

/// Desfaz o mapeamento e devolve o frame ao alocador.
///
/// Só use quando o frame tiver vindo de [`mapear_novo`]: liberar um frame que
/// pertence a outro dono o coloca de volta em circulação enquanto ainda está
/// em uso.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn desmapear_e_liberar(virtual_: u64) -> Result<(), &'static str> {
    let frame = arch::desmapear(virtual_)?;
    crate::frames::liberar(frame);
    Ok(())
}

/// Um espaço de endereços, dono das tabelas que o descrevem.
///
/// # Por que RAII, e não um par criar/destruir
///
/// Porque o dono de um espaço é um fio, e um fio pode morrer de várias
/// maneiras: saindo, tomando uma falha de proteção, ou sendo arrancado quando
/// a vaga dele é reaproveitada. Um `destruir` explícito teria de ser chamado
/// em todos esses caminhos, e o que se esquece de fazer em um deles vaza
/// tabelas até a memória física acabar.
///
/// Com o `Drop`, quem esquece é o compilador — e ele não esquece. É o mesmo
/// arranjo que [`crate::fios::pilha::Pilha`] usa pelo mesmo motivo.
pub struct Espaco {
    raiz: u64,
    privada: usize,
}

impl Espaco {
    /// Cria um espaço com o kernel mapeado e a entrada `privada` vazia.
    pub fn novo(privada: usize) -> Result<Self, &'static str> {
        Ok(Self {
            raiz: arch::criar_espaco(privada)?,
            privada,
        })
    }

    /// A raiz, para instalar no registrador de tradução.
    pub fn raiz(&self) -> u64 {
        self.raiz
    }
}

impl Drop for Espaco {
    fn drop(&mut self) {
        // Destruir o espaço em que se executa seria ficar sem tradução no meio
        // do caminho. Não pode acontecer — o escalonador troca para o espaço
        // do fio que entra antes que este seja largado —, mas o custo de
        // conferir é uma comparação e o custo de não conferir é a máquina.
        if arch::espaco_atual() == self.raiz {
            crate::log_error!("mmu", "espaco {:#x} largado enquanto ativo", self.raiz);
            return;
        }

        // SAFETY: a raiz veio de `criar_espaco`, não está ativa (conferido
        // acima) e ninguém mais a referencia — somos o dono, e estamos sendo
        // largados.
        unsafe { arch::destruir_espaco(self.raiz, self.privada) };
    }
}
