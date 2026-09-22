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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{Permissoes, TAMANHO_PAGINA};

use super::{BASE, TETO};

/// Onde a pilha do processo termina (o endereço mais alto, exclusivo).
const TOPO_DA_PILHA: u64 = TETO;
/// Primeira página da pilha.
const BASE_DA_PILHA: u64 = TETO - TAMANHO_PAGINA;
/// A página não mapeada logo abaixo da pilha.
const GUARD_DA_PILHA: u64 = BASE_DA_PILHA - TAMANHO_PAGINA;

/// Quantas páginas de código o processo que está mapeado ocupa.
///
/// # Por que um estado global
///
/// Porque o espaço do usuário está num endereço **fixo**, e por isso só cabe
/// um processo por vez. Não é uma simplificação gratuita: dois processos no
/// mesmo espaço de endereços precisariam ocupar faixas diferentes, e aí não
/// haveria isolamento nenhum entre eles — só a ilusão dele.
///
/// O isolamento de verdade vem com uma tabela de tradução por processo, que é
/// o passo seguinte. Aí cada um vê o mesmo `BASE` apontando para páginas
/// diferentes, e este contador vira um campo do processo.
static PAGINAS_MAPEADAS: spin::Mutex<Option<u64>> = spin::Mutex::new(None);

/// O fio que ocupa o espaço do usuário agora, ou zero se ele está livre.
///
/// # O que isto impede
///
/// [`descarregar`] é destrutivo, e [`carregar`] o chama antes de qualquer
/// coisa. Sem um dono, dois fios hospedeiros concorrentes produziriam isto: o
/// segundo desmapearia o código e a pilha do primeiro **enquanto ele roda**.
///
/// O desfecho pior não é o processo morrer — é o primeiro fio estar dentro de
/// uma chamada de sistema, já tendo passado por [`super::validar_faixa`], e ler
/// a memória do usuário depois de ela sumir. Aí a falha de página acontece com
/// o kernel no comando, e uma falha de página do kernel é fatal. Uma chamada
/// de `user.run` a mais derrubaria a máquina.
///
/// # Por que um atômico, e não uma trava
///
/// Porque a resposta que interessa — "o dono ainda está vivo?" — mora no
/// escalonador, e perguntar a ele exige a trava dele. Com um atômico aqui,
/// nenhuma trava deste módulo está na mão quando isso acontece. O módulo
/// [`crate::fios`] já registra o critério: aninhar travas é o começo de todo
/// deadlock, e manter a ordem trivial é mais barato que provar que ela é
/// segura.
static FIO_DONO: AtomicU64 = AtomicU64::new(0);

/// Toma o espaço do usuário para o fio atual, ou recusa.
///
/// Um dono que já terminou não bloqueia ninguém: o espaço é dele até morrer, e
/// depois disso é de quem chegar. É por isso que não existe nenhuma função
/// para "devolver" o espaço — devolver é algo que se esquece de fazer, e o
/// esquecimento só apareceria muito depois, na forma de um `user.run` que
/// recusa para sempre. A morte do fio é um fato que não se esquece de
/// acontecer.
fn reivindicar() -> Result<(), &'static str> {
    let eu = crate::fios::id_atual();
    if eu == 0 {
        return Err("este fio nao tem identificador proprio");
    }

    loop {
        let dono = FIO_DONO.load(Ordering::Acquire);

        // Já é nosso: um fio pode trocar o próprio programa.
        if dono == eu {
            return Ok(());
        }
        if dono != 0 && crate::fios::esta_vivo(dono) {
            return Err("o espaco do usuario ja tem um processo");
        }

        // Livre ou abandonado por um fio morto. Trocar em um passo só é o que
        // impede que dois fios concluam ao mesmo tempo que estava livre.
        if FIO_DONO
            .compare_exchange(dono, eu, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }

        // Alguém chegou antes entre a leitura e a troca. A volta seguinte
        // encontra esse alguém vivo e recusa — o laço não gira mais que isso.
    }
}

/// Há um processo vivo ocupando o espaço do usuário?
///
/// Consulta sem tomar nada, para quem precisa **reportar** o estado — o canal
/// do agente — e não para quem vai carregar. Entre esta resposta e uma carga o
/// estado pode mudar; quem carrega usa [`carregar`], que decide e toma o
/// espaço num passo só. Serve para o agente receber a recusa na resposta da
/// chamada, em vez de um `launched: true` seguido de nada acontecer.
pub fn ocupado() -> bool {
    let dono = FIO_DONO.load(Ordering::Acquire);
    dono != 0 && crate::fios::esta_vivo(dono)
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

/// Mapeia o código e a pilha de um processo.
///
/// O código é copiado enquanto a página ainda é gravável e só então passa a
/// executável e somente leitura. É a ordem que mantém `W^X`: em nenhum
/// instante existe uma página que o usuário possa escrever **e** executar.
pub fn carregar(codigo: &[u8]) -> Result<Programa, &'static str> {
    if codigo.is_empty() {
        return Err("programa vazio");
    }

    // Antes de destruir o que estiver mapeado, garantir que não é de ninguém.
    reivindicar()?;

    // O processo anterior pode ter terminado deixando as páginas dele no
    // lugar. Limpar **aqui**, e não no caminho que o encerra, é deliberado:
    // um processo termina de dentro de um handler de exceção — a chamada de
    // sistema `sair`, ou a falha que o matou —, e desmapear de lá faria um
    // handler tomar as travas da paginação e dos frames e percorrer tabelas.
    // Aqui estamos em contexto de fio, com tempo de sobra.
    descarregar();

    let paginas_de_codigo = (codigo.len() as u64).div_ceil(TAMANHO_PAGINA);
    if BASE + paginas_de_codigo * TAMANHO_PAGINA > GUARD_DA_PILHA {
        return Err("programa nao cabe no espaco do usuario");
    }

    // Fase 1: gravável, para podermos copiar.
    for i in 0..paginas_de_codigo {
        crate::paginacao::mapear_novo(BASE + i * TAMANHO_PAGINA, Permissoes::DADOS_USUARIO)?;
    }

    // SAFETY: as páginas acabaram de ser mapeadas e são exclusivas deste
    // processo; `paginas_de_codigo` foi calculado para caber `codigo` inteiro.
    unsafe {
        core::ptr::copy_nonoverlapping(codigo.as_ptr(), BASE as *mut u8, codigo.len());
    }

    // Fase 2: executável e somente leitura. Desmapear e remapear o mesmo frame
    // é o caminho que a API de paginação já oferece; o intervalo entre as duas
    // operações não é observável porque ninguém mais alcança este endereço.
    for i in 0..paginas_de_codigo {
        let endereco = BASE + i * TAMANHO_PAGINA;
        let frame = crate::arch::desmapear(endereco)?;
        // SAFETY: o frame acabou de sair deste mesmo endereço virtual, então
        // não está em uso por nenhum outro mapeamento.
        unsafe { crate::arch::mapear_frame(endereco, frame, Permissoes::CODIGO_USUARIO)? };
    }

    crate::paginacao::mapear_novo(BASE_DA_PILHA, Permissoes::DADOS_USUARIO)?;

    crate::arch::sem_interrupcoes(|| *PAGINAS_MAPEADAS.lock() = Some(paginas_de_codigo));

    Ok(Programa {
        entrada: BASE,
        // As duas ABIs exigem alinhamento de 16 no ponteiro de pilha.
        topo_da_pilha: TOPO_DA_PILHA & !0xF,
    })
}

/// Desmapeia o processo que estiver carregado, se houver.
///
/// Idempotente: chamar sem nada carregado não faz nada.
pub fn descarregar() {
    let Some(paginas) = crate::arch::sem_interrupcoes(|| PAGINAS_MAPEADAS.lock().take()) else {
        return;
    };

    for i in 0..paginas {
        liberar(BASE + i * TAMANHO_PAGINA);
    }
    liberar(BASE_DA_PILHA);
}

fn liberar(endereco: u64) {
    if let Err(motivo) = crate::paginacao::desmapear_e_liberar(endereco) {
        crate::log_error!("usuario", "pagina {:#x} nao voltou: {}", endereco, motivo);
    }
}

/// Carrega `codigo` e desce para o anel sem privilégio. Nunca retorna.
///
/// Precisa ser chamada de um fio criado por [`crate::fios::criar`]: o fio
/// inicial não tem pilha de kernel conhecida, e sem ela a primeira interrupção
/// que chegasse com o usuário rodando não teria para onde empilhar.
///
/// O mapeamento **sobrevive** a esta função: o processo continua executando
/// depois dela, e desmontá-lo aqui puxaria o chão de baixo dele. Quem o
/// desfaz é o próximo [`carregar`].
pub fn executar(codigo: &[u8]) -> Result<core::convert::Infallible, &'static str> {
    let programa = carregar(codigo)?;

    let pilha_de_kernel = crate::fios::pilha_de_kernel_atual();
    if pilha_de_kernel == 0 {
        return Err("este fio nao tem pilha de kernel propria");
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
