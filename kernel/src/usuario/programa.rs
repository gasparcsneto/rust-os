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

use super::{BASE, TETO};

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
const ENTRADA_PRIVADA: usize = crate::arch::ENTRADA_PRIVADA as usize;

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

    let paginas_de_codigo = (codigo.len() as u64).div_ceil(TAMANHO_PAGINA);
    if BASE + paginas_de_codigo * TAMANHO_PAGINA > GUARD_DA_PILHA {
        return Err("programa nao cabe no espaco do usuario");
    }

    // O espaço próprio vem antes de qualquer mapeamento, porque é *nele* que
    // os mapeamentos precisam cair. Entregá-lo ao fio antes de instalá-lo é o
    // que garante que ele seja devolvido mesmo que algo abaixo falhe: a partir
    // daqui quem o destrói é a morte do fio, não um caminho de erro.
    let espaco = crate::paginacao::Espaco::novo(ENTRADA_PRIVADA)?;
    let raiz = espaco.raiz();
    let anterior = crate::fios::adotar_espaco(espaco);

    // SAFETY: a raiz saiu de `Espaco::novo`, que copia as entradas de topo do
    // kernel — então o código que executa esta linha e a pilha deste fio
    // seguem mapeados do outro lado da troca.
    unsafe { crate::arch::trocar_espaco(raiz) };

    // Só agora: o espaço anterior deste fio, se havia, deixou de estar ativo.
    drop(anterior);

    // Fase 1: gravável, para podermos copiar.
    for i in 0..paginas_de_codigo {
        crate::paginacao::mapear_novo(BASE + i * TAMANHO_PAGINA, Permissoes::DADOS_USUARIO)?;
    }

    // SAFETY: as páginas acabaram de ser mapeadas no espaço deste processo e
    // são exclusivas dele; `paginas_de_codigo` foi calculado para caber
    // `codigo` inteiro.
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

    Ok(Programa {
        entrada: BASE,
        // As duas ABIs exigem alinhamento de 16 no ponteiro de pilha.
        topo_da_pilha: TOPO_DA_PILHA & !0xF,
    })
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
