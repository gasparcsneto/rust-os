//! Carrega um programa de usuário e o coloca para rodar.
//!
//! # Por que não um ELF, ainda
//!
//! Um carregador de ELF é um parser de formato binário: cabeçalhos, tabela de
//! segmentos, relocações. Nada disso é difícil, mas é **outra** coisa difícil,
//! e depurar duas de uma vez é o jeito mais confiável de não entender nenhuma.
//!
//! Aqui o programa é um punhado de bytes de instrução, copiado para uma página
//! e executado a partir do primeiro. Isso deixa a travessia de privilégio
//! sozinha em cena: se algo falhar, foi ela.
//!
//! # O mapa que o processo enxerga
//!
//! ```text
//!   BASE          ┌──────────────┐
//!                 │    código    │  usuário, executável, somente leitura
//!                 ├──────────────┤
//!                 │      …       │  não mapeado
//!   TETO - 8 KiB  ├──────────────┤
//!                 │  guard page  │  não mapeada
//!   TETO - 4 KiB  ├──────────────┤
//!                 │    pilha     │  usuário, gravável, não executável
//!   TETO          └──────────────┘
//! ```
//!
//! A guard page abaixo da pilha do processo existe pelo mesmo motivo da que
//! existe abaixo das pilhas do kernel: um estouro precisa virar falha no ponto
//! em que acontece, não corrupção do que estiver ao lado.

use crate::arch::{Permissoes, TAMANHO_PAGINA};

use super::TETO;

/// Onde a pilha do processo termina (o endereço mais alto, exclusivo).
const TOPO_DA_PILHA: u64 = TETO;
/// Primeira página da pilha.
const BASE_DA_PILHA: u64 = TETO - TAMANHO_PAGINA;
/// A página não mapeada logo abaixo da pilha.
const GUARD_DA_PILHA: u64 = BASE_DA_PILHA - TAMANHO_PAGINA;

/// Qual entrada da tabela de topo pertence ao processo.
///
/// Todo o espaço do usuário cabe nesta única entrada, e é ela que fica vazia
/// na tabela de cada processo — conferido em tempo de compilação junto de
/// [`BASE`] e [`TETO`].
pub const ENTRADA_PRIVADA: usize = crate::arch::ENTRADA_PRIVADA as usize;

/// Os programas que o kernel carrega consigo, procuráveis por nome.
///
/// # Por que uma tabela, e não um caminho de arquivo
///
/// Porque não há sistema de arquivos ainda. `exec` precisa de *alguma* forma
/// de dizer qual programa carregar, e um número de índice seria uma ABI que
/// envelhece mal — acrescentar um programa no meio renumeraria os outros.
///
/// Um nome é o que um `execve` de verdade recebe. No dia em que houver disco,
/// o que muda é onde a busca acontece; a chamada de sistema continua a mesma.
/// Um programa embutido: o nome pelo qual `executar` o encontra e como obter
/// os bytes dele.
///
/// A imagem vem por função em vez de fatia porque os limites de cada programa
/// são símbolos que o linker resolve — não há como escrevê-los numa constante.
struct Embutido {
    nome: &'static str,
    imagem: fn() -> &'static [u8],
}

static EMBUTIDOS: &[Embutido] = &[
    Embutido {
        nome: "exemplo",
        imagem: super::exemplo::bytes,
    },
    Embutido {
        nome: "filho",
        imagem: super::exemplo::bytes_do_filho,
    },
    Embutido {
        nome: "invasor",
        imagem: super::exemplo::bytes_invasores,
    },
    Embutido {
        nome: "leitor",
        imagem: super::exemplo::bytes_do_leitor,
    },
];

/// Procura um programa embutido pelo nome, devolvendo a posição na tabela.
///
/// Continua sendo uma busca linear sobre a mesma tabela de sempre. O que
/// mudou é quem chama: não é mais `executar`, e sim
/// [`crate::vfs::programas`] — que apresenta esta tabela como um sistema de
/// arquivos montado em `/bin`.
///
/// A posição é o que o sistema de arquivos usa como identificador do nó. Ela
/// serve porque a tabela é `static`: não há como uma entrada mudar de lugar
/// entre uma consulta e a leitura seguinte. A versão que devolvia só a imagem
/// saiu junto — com o VFS no meio, ninguém mais a chamava.
pub fn embutido_com_indice(nome: &str) -> Option<(usize, &'static [u8])> {
    EMBUTIDOS
        .iter()
        .position(|e| e.nome == nome)
        .map(|i| (i, (EMBUTIDOS[i].imagem)()))
}

/// A imagem do programa que está na posição `indice`.
pub fn embutido_por_indice(indice: usize) -> Option<&'static [u8]> {
    EMBUTIDOS.get(indice).map(|e| (e.imagem)())
}

/// O nome do programa que está na posição `indice`.
pub fn nome_por_indice(indice: usize) -> Option<&'static str> {
    EMBUTIDOS.get(indice).map(|e| e.nome)
}

/// O que sobrou do processo depois de uma carga que falhou.
///
/// # Por que a distinção importa
///
/// Porque `exec` tem um ponto de não retorno, e só depois dele é que "não há
/// para onde voltar" é verdade. Antes dele o processo que chamou continua
/// inteiro: a imagem dele está mapeada, a pilha dele está no lugar, e o
/// desfecho certo é devolver um erro — que é o que um `execve` faz quando
/// recusa o arquivo.
///
/// Sem esta distinção os dois casos eram um só, e o tratamento era o do pior
/// deles: qualquer falha matava o processo. Uma imagem malformada e uma falta
/// momentânea de memória, as duas recuperáveis, custavam o processo inteiro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// Falhou antes de trocar o espaço de endereços.
    ///
    /// O processo que chamou está intacto, e quem chamou pode devolver um
    /// erro para ele.
    ProcessoIntacto(&'static str),
    /// Falhou depois da troca.
    ///
    /// A imagem anterior não existe mais e a nova não chegou a ficar de pé.
    /// Encerrar é o único desfecho honesto.
    SemVolta(&'static str),
}

impl Falha {
    /// O motivo, para o log e para o relatório do agente.
    pub fn motivo(&self) -> &'static str {
        match self {
            Falha::ProcessoIntacto(motivo) | Falha::SemVolta(motivo) => motivo,
        }
    }
}

/// Um programa mapeado, pronto para executar.
pub struct Programa {
    entrada: u64,
    topo_da_pilha: u64,
}

impl Programa {
    pub fn entrada(&self) -> u64 {
        self.entrada
    }

    /// Ponteiro de pilha inicial, alinhado como as duas ABIs exigem.
    pub fn topo_da_pilha(&self) -> u64 {
        self.topo_da_pilha
    }
}

/// Mapeia os segmentos de um ELF e a pilha de um processo.
///
/// # A ordem, e por que ela mantém `W^X`
///
/// Todo segmento é mapeado primeiro como **gravável e não executável**, para
/// que o conteúdo possa ser copiado e o resto zerado. Só depois cada um recebe
/// as permissões que pediu. Em nenhum instante existe uma página que o usuário
/// possa escrever *e* executar — e é por isso que a segunda passada existe em
/// vez de mapear já com a permissão final.
///
/// # Por que segmentos que dividem página são recusados
///
/// Permissão é propriedade da página, não do segmento. Dois segmentos na mesma
/// página teriam de negociar, e a única negociação segura seria conceder a
/// união das permissões — que é exatamente como se perde o `W^X`. Um linker
/// alinha segmentos a página justamente por isso, então recusar não rejeita
/// nada legítimo.
pub fn carregar(imagem: &[u8]) -> Result<Programa, Falha> {
    // Tudo até a troca de espaço é recuperável, e é este `map_err` que diz
    // isso uma vez em vez de em cada `?`.
    let antes = Falha::ProcessoIntacto;

    let elf = super::elf::validar(imagem).map_err(antes)?;

    // As faixas de página de cada segmento, conferidas antes de qualquer
    // mapeamento: descobrir a sobreposição no meio da carga deixaria o espaço
    // meio montado.
    let mut faixas = [(0u64, 0u64); super::elf::MAX_SEGMENTOS];
    let segmentos = elf.segmentos();
    for (i, segmento) in segmentos.iter().enumerate() {
        faixas[i] =
            faixa_de_paginas(segmento.destino, segmento.bytes_na_memoria as u64).map_err(antes)?;
    }
    for i in 0..segmentos.len() {
        for j in (i + 1)..segmentos.len() {
            if faixas[i].0 < faixas[j].1 && faixas[j].0 < faixas[i].1 {
                return Err(antes("dois segmentos dividem a mesma pagina"));
            }
        }
        // A pilha é do kernel para dar, não do programa para pedir.
        if faixas[i].0 < TOPO_DA_PILHA && GUARD_DA_PILHA < faixas[i].1 {
            return Err(antes("um segmento invade a pilha do processo"));
        }
    }

    // O espaço próprio vem antes de qualquer mapeamento, porque é *nele* que
    // os mapeamentos precisam cair. Entregá-lo ao fio antes de instalá-lo é o
    // que garante que ele seja devolvido mesmo que algo abaixo falhe: a partir
    // daqui quem o destrói é a morte do fio, não um caminho de erro.
    // O último passo recuperável. Depois de `adotar_espaco` o fio já é dono do
    // espaço novo, e o antigo só pode ser largado do outro lado da troca — não
    // há mais como voltar atrás sem largar um espaço ativo.
    let espaco = crate::paginacao::Espaco::novo(ENTRADA_PRIVADA).map_err(antes)?;
    let raiz = espaco.raiz();
    let anterior = crate::fios::adotar_espaco(espaco);

    // SAFETY: a raiz saiu de `Espaco::novo`, que copia as entradas de topo do
    // kernel — então o código que executa esta linha e a pilha deste fio
    // seguem mapeados do outro lado da troca.
    unsafe { crate::arch::trocar_espaco(raiz) };

    // Só agora: o espaço anterior deste fio, se havia, deixou de estar ativo.
    drop(anterior);

    for (i, segmento) in segmentos.iter().enumerate() {
        let permissoes = Permissoes {
            escrita: segmento.escrita,
            executavel: segmento.executavel,
            dispositivo: false,
            usuario: true,
        };

        let (inicio, fim) = faixas[i];
        let conteudo = elf.conteudo(segmento);

        crate::paginacao::mapear_faixa_preenchendo(
            inicio,
            (fim - inicio) / TAMANHO_PAGINA,
            permissoes,
            || {
                // SAFETY: as páginas que cobrem
                // `[destino, destino + bytes_na_memoria)` estão mapeadas com
                // escrita no espaço deste processo enquanto esta closure roda,
                // e o validador garantiu que a faixa inteira está no espaço do
                // usuário.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        conteudo.as_ptr(),
                        segmento.destino as *mut u8,
                        conteudo.len(),
                    );

                    // O que o segmento pede além do que o arquivo traz é a
                    // `.bss`, e ela **precisa** chegar zerada. `mapear_novo` já
                    // entrega páginas limpas, mas depender disso seria depender
                    // de um detalhe de outro módulo para uma garantia que é
                    // deste.
                    let resto = segmento.bytes_na_memoria - conteudo.len();
                    core::ptr::write_bytes(
                        (segmento.destino + conteudo.len() as u64) as *mut u8,
                        0,
                        resto,
                    );
                }
            },
        )
        .map_err(Falha::SemVolta)?;
    }

    crate::paginacao::mapear_novo(BASE_DA_PILHA, Permissoes::DADOS_USUARIO)
        .map_err(Falha::SemVolta)?;

    Ok(Programa {
        entrada: elf.entrada(),
        // As duas ABIs exigem alinhamento de 16 no ponteiro de pilha.
        topo_da_pilha: TOPO_DA_PILHA & !0xF,
    })
}

/// As páginas que cobrem `[inicio, inicio + tamanho)`.
///
/// Devolve `[primeira, fim_exclusivo)`, os dois alinhados a página. O
/// arredondamento para cima usa `div_ceil` em vez de somar `TAMANHO_PAGINA - 1`
/// porque os dois números vêm do arquivo, e a soma transbordaria em silêncio.
fn faixa_de_paginas(inicio: u64, tamanho: u64) -> Result<(u64, u64), &'static str> {
    let primeira = inicio & !(TAMANHO_PAGINA - 1);
    let fim = inicio
        .checked_add(tamanho)
        .ok_or("segmento com tamanho que transborda")?;
    let ultima = fim.div_ceil(TAMANHO_PAGINA) * TAMANHO_PAGINA;
    Ok((primeira, ultima.max(primeira + TAMANHO_PAGINA)))
}

/// Carrega `codigo` e desce para o anel sem privilégio. Nunca retorna.
///
/// Precisa ser chamada de um fio criado por [`crate::fios::criar`]: o fio
/// inicial não tem pilha de kernel conhecida, e sem ela a primeira interrupção
/// que chegasse com o usuário rodando não teria para onde empilhar.
///
/// O mapeamento **sobrevive** a esta função: o processo continua executando
/// depois dela, e desmontá-lo aqui puxaria o chão de baixo dele. Quem o desfaz
/// é a morte deste fio, que larga o espaço de endereços inteiro de uma vez.
pub fn executar(imagem: &[u8]) -> Result<core::convert::Infallible, Falha> {
    let programa = carregar(imagem)?;

    let pilha_de_kernel = crate::fios::pilha_de_kernel_atual();
    if pilha_de_kernel == 0 {
        // Depois da carga, portanto depois da troca: o espaço anterior deste
        // fio já não existe.
        return Err(Falha::SemVolta("este fio nao tem pilha de kernel propria"));
    }

    let entrada = programa.entrada();
    let pilha = programa.topo_da_pilha();

    crate::log_info!(
        "usuario",
        "entrando em userspace: codigo {:#x}, pilha {:#x}",
        entrada,
        pilha
    );

    // SAFETY: código e pilha foram mapeados agora com permissão de usuário, e
    // a pilha de kernel deste fio foi informada logo acima.
    unsafe {
        crate::arch::definir_pilha_de_kernel(pilha_de_kernel);
        crate::arch::entrar_em_usuario(entrada, pilha)
    }
}
