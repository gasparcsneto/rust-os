//! Carrega um programa de usuário e o coloca para rodar.
//!
//! # De bytes soltos a ELF
//!
//! A primeira versão deste arquivo carregava um punhado de bytes de
//! instrução numa página e os executava a partir do primeiro — de propósito,
//! para deixar a travessia de privilégio sozinha em cena. Hoje o programa é um
//! ELF64: [`carregar`] o valida por [`super::elf`], mapeia cada segmento com a
//! permissão que ele pede e nunca deixa existir uma página gravável e
//! executável ao mesmo tempo. O que continua deste arquivo é a pilha, com a
//! guarda abaixo dela, e a descida de privilégio.
//!
//! # O mapa que o processo enxerga
//!
//! ```text
//!   BASE          ┌──────────────┐
//!                 │    código    │  usuário, executável, somente leitura
//!                 ├──────────────┤
//!                 │      …       │  não mapeado
//!   TETO - 68 KiB ├──────────────┤
//!                 │  guard page  │  não mapeada
//!   TETO - 64 KiB ├──────────────┤
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
/// Primeira página da pilha — ver [`protocolo::usuario::PAGINAS_DA_PILHA`]
/// sobre por que são dezesseis, e não mais uma só.
const BASE_DA_PILHA: u64 = TETO - protocolo::usuario::PAGINAS_DA_PILHA * TAMANHO_PAGINA;
/// A página não mapeada logo abaixo da pilha.
const GUARD_DA_PILHA: u64 = BASE_DA_PILHA - TAMANHO_PAGINA;

/// Qual entrada da tabela de topo pertence ao processo.
///
/// Todo o espaço do usuário cabe nesta única entrada, e é ela que fica vazia
/// na tabela de cada processo — conferido em tempo de compilação junto de
/// [`crate::usuario::BASE`] e [`crate::usuario::TETO`].
pub const ENTRADA_PRIVADA: usize = crate::arch::ENTRADA_PRIVADA as usize;

/// Os programas que o kernel carrega consigo, procuráveis por nome.
///
/// # Por que uma tabela, e não arquivos no disco
///
/// Porque estes programas nasceram antes do sistema de arquivos, junto do
/// assembly que os monta. A tabela continua sendo a origem dos bytes; quem a
/// apresenta como arquivos é [`crate::vfs::programas`], montado em `/bin`, e
/// `executar` os procura por caminho como procuraria qualquer outro.
///
/// Um nome, e não um índice, pelo mesmo motivo de um `execve`: acrescentar um
/// programa no meio não renumera os outros.
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
    Embutido {
        nome: "paciente",
        imagem: super::exemplo::bytes_do_paciente,
    },
    Embutido {
        nome: "orfao",
        imagem: super::exemplo::bytes_do_orfao,
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

/// Quantos programas o kernel carrega consigo.
///
/// Existe para a suíte, e por um motivo concreto: o caso que confere que a
/// raiz em Btrfs não rouba `/bin` comparava com um `4` escrito à mão. Ele
/// reprovou no dia em que o quinto programa entrou — não por um defeito, mas
/// porque o número morava longe da lista. Aqui ele não tem como divergir.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn quantos_embutidos() -> usize {
    EMBUTIDOS.len()
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
///
/// `editor` é quem selou a imagem, quando ela veio de fora da imagem do
/// sistema — conferido antes, por [`super::codigo::obter`]. Vai para o
/// programa do fio junto com o manifesto e o resumo.
pub fn carregar(imagem: &[u8], editor: Option<[u8; 32]>) -> Result<Programa, Falha> {
    // Tudo até a troca de espaço é recuperável — o primeiro passo —, a troca
    // não falha, e o que vem depois dela não tem volta: os dois `map_err`
    // dizem isso uma vez cada, em vez de em cada `?`.
    preparar(imagem, editor)
        .map_err(Falha::ProcessoIntacto)?
        .trocar()
        .mapear()
        .map_err(Falha::SemVolta)
}

/// Uma imagem conferida e o espaço novo dela, ainda não adotado: tudo o que
/// [`carregar`] faz antes do ponto sem volta.
///
/// O processo que chamou segue intacto — a imagem dele mapeada, a pilha no
/// lugar. Largar uma `Preparada` sem [`trocar`](Preparada::trocar) larga só
/// o espaço novo, que nunca esteve ativo: é recusar como recusa uma falha
/// [`Falha::ProcessoIntacto`].
///
/// # Por que em três passos
///
/// Para quem precisa de alguma coisa **no** ponto sem volta, e só pode
/// tentá-la antes dele: a troca de imagem de um processo que é ponta de
/// fluxo toma a ordem das gravações, sem esperar, entre o primeiro passo e
/// o segundo, e a segura só pelo segundo — a troca, que não falha — e pelo
/// fim dos fluxos; o terceiro ([`Trocada::mapear`]) vem com ela já solta —
/// ver `usuario::executar`. Ouvindo que ela está com outro fio, larga a
/// preparada, e o processo continua o que era.
pub struct Preparada<'a> {
    elf: super::elf::Imagem<'a>,
    faixas: [(u64, u64); super::elf::MAX_SEGMENTOS],
    programa: crate::autorizacao::Programa,
    espaco: crate::paginacao::Espaco,
}

/// O primeiro passo de [`carregar`]: a imagem conferida — o ELF, as faixas
/// de página dos segmentos, o manifesto —, o programa que ela é, e o espaço
/// novo, criado e ainda não adotado. Um erro aqui deixa o processo intacto.
pub fn preparar(imagem: &[u8], editor: Option<[u8; 32]>) -> Result<Preparada<'_>, &'static str> {
    let elf = super::elf::validar(imagem)?;

    // As faixas de página de cada segmento, conferidas antes de qualquer
    // mapeamento: descobrir a sobreposição no meio da carga deixaria o espaço
    // meio montado.
    let mut faixas = [(0u64, 0u64); super::elf::MAX_SEGMENTOS];
    let segmentos = elf.segmentos();
    for (i, segmento) in segmentos.iter().enumerate() {
        faixas[i] = faixa_de_paginas(segmento.destino, segmento.bytes_na_memoria as u64)?;
    }
    for i in 0..segmentos.len() {
        for j in (i + 1)..segmentos.len() {
            if faixas[i].0 < faixas[j].1 && faixas[j].0 < faixas[i].1 {
                return Err("dois segmentos dividem a mesma pagina");
            }
        }
        // A pilha é do kernel para dar, não do programa para pedir.
        if faixas[i].0 < TOPO_DA_PILHA && GUARD_DA_PILHA < faixas[i].1 {
            return Err("um segmento invade a pilha do processo");
        }
    }

    // O programa que a imagem é: o manifesto que ela declara — lido aqui,
    // onde recusar ainda deixa o processo intacto — e o resumo dela. Um
    // manifesto que não se lê recusa a imagem: não é um manifesto vazio.
    let manifesto = match elf.manifesto() {
        Some(texto) => Some(politica::manifesto::ler(texto).map_err(|e| e.motivo())?),
        None => None,
    };
    let programa = crate::autorizacao::Programa::Imagem {
        manifesto,
        resumo: politica::manifesto::resumo_da_imagem(imagem),
        editor,
    };

    // O espaço próprio vem antes de qualquer mapeamento, porque é *nele* que
    // os mapeamentos precisam cair. É o último passo recuperável: largado
    // antes de o fio adotá-lo, ele nunca esteve ativo.
    let espaco = crate::paginacao::Espaco::novo(ENTRADA_PRIVADA)?;
    Ok(Preparada {
        elf,
        faixas,
        programa,
        espaco,
    })
}

impl<'a> Preparada<'a> {
    /// O segundo passo de [`carregar`]: o ponto sem volta — o fio adota o
    /// espaço novo e o programa da imagem, e o espaço novo, ainda vazio,
    /// passa a ser o ativo. Não falha, e não volta: a imagem anterior deixa
    /// de existir aqui, e o que era dela — o espaço e a resposta que ela não
    /// buscou — vai com a [`Trocada`], para sair no terceiro passo.
    pub fn trocar(self) -> Trocada<'a> {
        let Preparada {
            elf,
            faixas,
            programa,
            espaco,
        } = self;

        // Entregar o espaço ao fio antes de instalá-lo é o que garante que
        // ele seja devolvido mesmo que algo depois falhe: a partir daqui quem
        // o destrói é a morte do fio, não um caminho de erro. Depois de
        // `adotar_imagem` o fio já é dono do espaço novo, e o antigo só pode
        // ser largado do outro lado da troca — não há mais como voltar atrás
        // sem largar um espaço ativo.
        let raiz = espaco.raiz();
        // O espaço e o programa trocam juntos: a imagem nova nunca roda com o
        // manifesto da anterior, nem a anterior com o da nova.
        let (anterior, resposta_da_anterior) = crate::fios::adotar_imagem(espaco, programa);

        // SAFETY: a raiz saiu de `Espaco::novo`, que copia as entradas de
        // topo do kernel — então o código que executa esta linha e a pilha
        // deste fio seguem mapeados do outro lado da troca.
        unsafe { crate::arch::trocar_espaco(raiz) };

        Trocada {
            elf,
            faixas,
            anterior,
            resposta_da_anterior,
        }
    }
}

/// A imagem nova adotada — o espaço dela ativo e ainda vazio, e o programa
/// dela já o do fio — e o que era da anterior, por largar: o que o segundo
/// passo de [`carregar`] deixa para o terceiro, [`Trocada::mapear`].
///
/// # Por que o resto vem à parte
///
/// Largar o espaço anterior desmonta-o página a página — tanto quanto o
/// processo tiver mapeado —, e mapear a imagem nova copia e zera os
/// segmentos — tanto quanto ela pedir. Nenhum dos dois precisa do ponto sem
/// volta, e quem o atravessa com a ordem das gravações na mão — a troca de
/// imagem de quem é ponta de fluxo — a solta antes deles: a ordem serializa
/// o journal, os comandos, as revogações e o coletor da máquina inteira, e
/// não espera por um trabalho que o processo dimensiona — ver
/// `usuario::executar`.
#[must_use = "a imagem nova precisa ser mapeada, e o que era da anterior, largado"]
pub struct Trocada<'a> {
    elf: super::elf::Imagem<'a>,
    faixas: [(u64, u64); super::elf::MAX_SEGMENTOS],
    anterior: Option<crate::paginacao::Espaco>,
    resposta_da_anterior: crate::fios::EstadoDoPedido,
}

impl Trocada<'_> {
    /// O terceiro passo de [`carregar`]: o que era da imagem anterior sai —
    /// o espaço dela, que deixou de estar ativo na troca, e a resposta que
    /// ela não buscou —, e os segmentos e a pilha da nova são mapeados no
    /// espaço dela. Um erro aqui é sem volta: a imagem anterior já não
    /// existe.
    pub fn mapear(self) -> Result<Programa, &'static str> {
        let Trocada {
            elf,
            faixas,
            anterior,
            resposta_da_anterior,
        } = self;

        // Na suíte: com que mão este trabalho roda — ver `carga_de_teste`.
        // No começo dele, para ir junto aonde ele for.
        #[cfg(feature = "modo-teste")]
        carga_de_teste::anotar();

        drop(resposta_da_anterior);
        // O espaço anterior deste fio, se havia, deixou de estar ativo na
        // troca.
        drop(anterior);

        // Na suíte: a falta de memória ao mapear, com a anterior já fora —
        // ver `super::falha_da_troca_de_teste`.
        #[cfg(feature = "modo-teste")]
        if super::falha_da_troca_de_teste::falhar(
            crate::fios::id_atual(),
            super::falha_da_troca_de_teste::Etapa::Mapeamento,
        ) {
            return Err(super::falha_da_troca_de_teste::MAPEAMENTO);
        }

        for (i, segmento) in elf.segmentos().iter().enumerate() {
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
                    // `[destino, destino + bytes_na_memoria)` estão mapeadas
                    // com escrita no espaço deste processo enquanto esta
                    // closure roda, e o validador garantiu que a faixa
                    // inteira está no espaço do usuário.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            conteudo.as_ptr(),
                            segmento.destino as *mut u8,
                            conteudo.len(),
                        );

                        // O que o segmento pede além do que o arquivo traz é
                        // a `.bss`, e ela **precisa** chegar zerada.
                        // `mapear_novo` já entrega páginas limpas, mas
                        // depender disso seria depender de um detalhe de
                        // outro módulo para uma garantia que é deste.
                        let resto = segmento.bytes_na_memoria - conteudo.len();
                        core::ptr::write_bytes(
                            (segmento.destino + conteudo.len() as u64) as *mut u8,
                            0,
                            resto,
                        );
                    }
                },
            )?;
        }

        for i in 0..protocolo::usuario::PAGINAS_DA_PILHA {
            crate::paginacao::mapear_novo(
                BASE_DA_PILHA + i * TAMANHO_PAGINA,
                Permissoes::DADOS_USUARIO,
            )?;
        }

        Ok(Programa {
            entrada: elf.entrada(),
            // As duas ABIs exigem alinhamento de 16 no ponteiro de pilha.
            topo_da_pilha: TOPO_DA_PILHA & !0xF,
        })
    }
}

/// Só para a suíte: com que mão o terceiro passo da carga
/// ([`crate::usuario::programa::Trocada::mapear`]) rodou para o processo
/// vigiado — com a ordem das gravações, ou sem ela. A troca de imagem de
/// quem é ponta de fluxo a solta antes dele, e os casos da troca com a
/// ordem com outro fio conferem. Fora da suíte não existe.
#[cfg(feature = "modo-teste")]
pub mod carga_de_teste {
    use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

    /// O processo vigiado, como `fio + 1`; zero, nenhum.
    static VIGIADO: AtomicU64 = AtomicU64::new(0);
    /// O que se viu: 0, nada ainda; 1, sem a ordem; 2, com ela.
    static VISTO: AtomicU8 = AtomicU8::new(0);

    /// Vigia a próxima carga do processo `fio`, e esquece o que se viu.
    pub fn vigiar(fio: u64) {
        VISTO.store(0, Ordering::Release);
        VIGIADO.store(fio + 1, Ordering::Release);
    }

    /// Para de vigiar — o caso que falha no meio não deixa a vigia armada
    /// para o seguinte.
    pub fn esquecer() {
        VIGIADO.store(0, Ordering::Release);
        VISTO.store(0, Ordering::Release);
    }

    /// Se a carga vigiada rodou com a ordem das gravações na mão; `None`, se
    /// ainda não rodou.
    pub fn com_a_ordem() -> Option<bool> {
        match VISTO.load(Ordering::Acquire) {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        }
    }

    /// Chamada no começo do terceiro passo.
    pub(super) fn anotar() {
        if VIGIADO.load(Ordering::Acquire) == crate::fios::id_atual() + 1 {
            let com = crate::persistencia::ordem_na_mao();
            VISTO.store(if com { 2 } else { 1 }, Ordering::Release);
        }
    }
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
// Os casos da suíte a chamam com imagens estáticas; em produção, quem lança
// é `usuario::lancar`, que carrega de uma imagem possuída e usa os dois
// passos — ver [`entrar`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn executar(imagem: &[u8]) -> Result<core::convert::Infallible, Falha> {
    entrar(carregar(imagem, None)?)
}

/// Desce para o anel sem privilégio num programa já carregado. Nunca
/// retorna.
///
/// # Por que separada de [`executar`]
///
/// Para quem carrega de uma imagem que **possui**: um `Vec` lido do disco.
/// `executar` recebe a imagem emprestada e não volta, então quem a possui
/// nunca chegaria a largá-la — o `Vec` ficava no heap do kernel para
/// sempre, um por programa lançado do disco. Carregar copia os segmentos
/// para as páginas do processo; entre carregar e entrar a imagem já não
/// serve para nada, e é ali que quem a possui a larga.
pub fn entrar(programa: Programa) -> Result<core::convert::Infallible, Falha> {
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
