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
