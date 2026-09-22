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

/// Mapeia uma faixa de páginas, deixa `preencher` escrever nelas, e **só
/// então** aplica as permissões pedidas.
///
/// # O que esta função existe para garantir
///
/// `W^X`: em nenhum instante existe uma página que o usuário possa escrever
/// *e* executar. Conseguir isso exige uma sequência de três passos numa ordem
/// específica — mapear gravável, preencher, repermissionar — e a sequência
/// estava escrita duas vezes, no carregador de ELF e na cópia de espaço do
/// `fork`.
///
/// Duas cópias de um invariante sutil é uma a mais do que se pode manter: o
/// dia em que uma delas ganhasse um caso novo, a outra continuaria certa por
/// conta própria até deixar de ser. Aqui a garantia mora num lugar só, e quem
/// mapeia memória de usuário passa por ele.
///
/// # Por que `preencher` não recebe ponteiro nenhum
///
/// Porque a faixa pode ter várias páginas e o conteúdo atravessá-las — é o
/// caso de um segmento de ELF. Dar um ponteiro por página obrigaria quem
/// chama a repartir o conteúdo; a closure escreve direto nos endereços
/// virtuais, que é onde eles estão.
///
/// Ela roda com as páginas **graváveis**, e é a única janela em que elas
/// estão: depois que esta função retorna, o que foi pedido somente leitura já
/// é somente leitura.
pub fn mapear_faixa_preenchendo(
    inicio: u64,
    paginas: u64,
    permissoes: Permissoes,
    preencher: impl FnOnce(),
) -> Result<(), &'static str> {
    // Gravável e nunca executável, aconteça o que acontecer com o resto: é
    // justamente essa combinação que torna a janela segura.
    let temporarias = Permissoes {
        escrita: true,
        executavel: false,
        ..permissoes
    };

    for i in 0..paginas {
        mapear_novo(inicio + i * TAMANHO_PAGINA, temporarias)?;
    }

    preencher();

    if permissoes == temporarias {
        return Ok(());
    }

    // Desmapear e remapear o mesmo frame é o caminho que a API de paginação
    // oferece para trocar permissões. O intervalo entre as duas operações não
    // é observável: ninguém mais alcança estes endereços.
    for i in 0..paginas {
        let endereco = inicio + i * TAMANHO_PAGINA;
        let frame = arch::desmapear(endereco)?;
        // SAFETY: o frame acabou de sair deste mesmo endereço virtual, então
        // não está em uso por nenhum outro mapeamento.
        unsafe { arch::mapear_frame(endereco, frame, permissoes)? };
    }
    Ok(())
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

    /// Um espaço novo com uma **cópia** das páginas de usuário do ativo.
    ///
    /// É o que `fork` precisa: o filho enxerga os mesmos endereços com o mesmo
    /// conteúdo, mas escrever num deles não alcança o outro.
    ///
    /// # Por que cópia integral, e não copy-on-write
    ///
    /// Porque copy-on-write é uma otimização, e otimizar antes de funcionar é
    /// a forma mais confiável de não conseguir nenhum dos dois. Ele exige
    /// contagem de referências por frame, marcar as páginas do **pai** como
    /// somente leitura e um caminho de falha de página que distinga "escrita
    /// proibida" de "escrita a resolver". Cada uma dessas peças tem um modo
    /// próprio de falhar em silêncio.
    ///
    /// O custo de copiar tudo é uma página por página mapeada, pago uma vez
    /// no `fork`. Para processos do tamanho dos que este kernel roda, é
    /// irrelevante — e o dia em que deixar de ser, o teste que compara o
    /// conteúdo dos dois lados continua valendo palavra por palavra.
    ///
    /// # Por que as permissões são lidas de volta das tabelas
    ///
    /// Porque recriar tudo gravável seria mais simples e destruiria o `W^X`
    /// do processo no instante em que ele tivesse um filho. O segmento de
    /// código do pai é somente leitura e executável; o do filho tem de ser a
    /// mesma coisa.
    pub fn clonar_o_ativo(privada: usize) -> Result<Self, &'static str> {
        // A origem é o espaço **ativo**, e não um `&self`, porque é assim que
        // `fork` o encontra: quem chama está executando dentro do espaço que
        // quer duplicar. Ler o registrador de tradução evita ter de alcançar o
        // espaço através do escalonador, que traria a trava dele junto.
        let origem = arch::espaco_atual();
        let novo = Self::novo(privada)?;

        // A lista é montada antes de qualquer troca de espaço: percorrer as
        // tabelas da origem e escrever no destino ao mesmo tempo exigiria que
        // os dois estivessem ativos, e só um pode estar.
        let mut paginas = alloc::vec::Vec::new();
        arch::sem_interrupcoes(|| {
            // SAFETY: a raiz é nossa e é válida; as interrupções mascaradas
            // garantem que ninguém altera as tabelas durante o percurso.
            unsafe {
                arch::percorrer_paginas_do_usuario(
                    origem,
                    privada,
                    &mut |virtual_, fisico, permissoes| {
                        paginas.push((virtual_, fisico, permissoes));
                    },
                );
            }
        });

        let anterior = arch::espaco_atual();

        // SAFETY: as duas raízes carregam as entradas de topo do kernel, então
        // o código e a pilha deste fio seguem mapeados dos dois lados. A troca
        // de volta acontece em qualquer desfecho, inclusive no de erro.
        let resultado = unsafe {
            arch::trocar_espaco(novo.raiz);
            let r = copiar_para_o_espaco_ativo(&paginas);
            arch::trocar_espaco(anterior);
            r
        };
        resultado?;
        Ok(novo)
    }
}

/// Recria no espaço ativo as páginas descritas, com o conteúdo do original.
///
/// # Safety
///
/// O espaço ativo precisa ser o destino, e cada `fisico` precisa ser um frame
/// vivo — o percurso que os produziu não pode ter sido invalidado no meio.
unsafe fn copiar_para_o_espaco_ativo(
    paginas: &[(u64, u64, arch::Permissoes)],
) -> Result<(), &'static str> {
    for (virtual_, fisico, permissoes) in paginas {
        mapear_faixa_preenchendo(*virtual_, 1, *permissoes, || {
            // SAFETY: a página de destino está mapeada com escrita neste
            // espaço — é o que `mapear_faixa_preenchendo` garante enquanto
            // esta closure roda —, e o mapa da memória física alcança o frame
            // de origem, que pertence ao outro espaço e por isso não tem
            // endereço virtual aqui.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    arch::acesso_fisico(*fisico),
                    *virtual_ as *mut u8,
                    TAMANHO_PAGINA as usize,
                );
            }
        })?;
    }
    Ok(())
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
