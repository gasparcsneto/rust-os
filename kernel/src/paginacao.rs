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

use core::sync::atomic::{AtomicU64, Ordering};

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
///
/// # O que acontece quando falha no meio
///
/// As páginas já mapeadas ficam onde estão. Isso é deliberado e não é um
/// vazamento **porque todo chamador de hoje mapeia dentro de um
/// [`Espaco`] que ele possui**: o `Drop` dele devolve tudo, mapeado pela
/// metade ou não. Quem chamar isto fora dessa condição precisa desfazer o que
/// ficou — a função não tem como saber a quem as páginas pertencem.
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

/// Mapeia no espaço ativo, a partir de `destino`, os mesmos frames que o
/// kernel enxerga a partir de `origem` — `paginas` páginas, graváveis pelo
/// usuário e marcadas como compartilhadas.
///
/// É como os pixels de uma superfície do compositor chegam ao processo: os
/// dois lados escrevem e leem a mesma memória física, e nada é copiado.
///
/// # Por que isto é seguro, se `mapear_frame` pede um frame sem uso
///
/// Porque cada frame ganha um dono a mais **antes** de ser mapeado — a
/// mesma coreografia do `fork`. O compositor e o processo passam a soltá-lo
/// cada um por si: o `Drop` da memória da superfície de um lado, a
/// destruição do espaço do outro. O frame volta ao alocador com o último
/// dos dois, em qualquer ordem.
///
/// # Tudo ou nada
///
/// Uma falha no meio desfaz as páginas já mapeadas, com os donos que elas
/// ganharam: um erro com metade da superfície no processo deixaria frames
/// com um dono que nenhum espaço representa.
pub fn espelhar_no_usuario(origem: u64, destino: u64, paginas: u64) -> Result<(), &'static str> {
    let permissoes = Permissoes::DADOS_USUARIO;
    for i in 0..paginas {
        let virtual_ = destino + i * TAMANHO_PAGINA;
        let feito = (|| {
            let frame =
                arch::traduzir(origem + i * TAMANHO_PAGINA).ok_or("superficie sem pagina")?;
            if !crate::frames::compartilhar(frame) {
                return Err("frame da superficie nao pode ser compartilhado");
            }
            // SAFETY: o frame é da superfície e acaba de ganhar um dono a
            // mais, então não volta ao alocador enquanto este mapeamento
            // existir — o caso que o contrato de `mapear_frame` deixa ao
            // chamador, satisfeito pela contagem de donos.
            if let Err(motivo) = unsafe { arch::mapear_frame(virtual_, frame, permissoes) } {
                crate::frames::soltar(frame);
                return Err(motivo);
            }
            arch::marcar_compartilhada(virtual_)
        })();
        if let Err(motivo) = feito {
            // A página `i` pode ter ficado mapeada sem a marca — o mapeamento
            // deu certo e a marca não. Desfazer até ela também é o que deixa
            // a contagem certa: `desfazer_espelho` só desfaz a página que
            // aponta para o frame da origem.
            desfazer_espelho(origem, destino, i + 1);
            return Err(motivo);
        }
    }
    Ok(())
}

/// Desfaz o que [`espelhar_no_usuario`] fez: no espaço ativo, desmapeia
/// cada página a partir de `destino` que aponta para o mesmo frame que a
/// página correspondente a partir de `origem`, e solta o dono que ela
/// ganhou.
///
/// # Por que conferir o frame, e não só desmapear
///
/// Porque quem desfaz nem sempre é quem espelhou, no mesmo instante. Uma
/// superfície fechada depois de um `exec` tem o endereço antigo no espaço de
/// um programa novo, que pode ter posto a própria memória ali. Desmapear às
/// cegas arrancaria a memória do programa novo — e soltaria um dono que não
/// era da superfície.
///
/// A conferência é exata porque os frames da origem estão vivos enquanto
/// ela existir: nenhum outro mapeamento pode ter recebido um deles do
/// alocador. Um endereço que aponta para um deles é o espelho, e nenhum
/// outro.
pub fn desfazer_espelho(origem: u64, destino: u64, paginas: u64) {
    for i in 0..paginas {
        let virtual_ = destino + i * TAMANHO_PAGINA;
        let Some(esperado) = arch::traduzir(origem + i * TAMANHO_PAGINA) else {
            continue;
        };
        if arch::traduzir(virtual_) != Some(esperado) {
            continue;
        }
        if let Ok(frame) = arch::desmapear(virtual_) {
            crate::frames::soltar(frame);
        }
    }
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

    /// Um espaço novo que enxerga a mesma memória do ativo, **copiando cada
    /// página só quando alguém escrever nela**.
    ///
    /// É o que `fork` precisa: o filho enxerga os mesmos endereços com o
    /// mesmo conteúdo, e escrever num deles não alcança o outro.
    ///
    /// # Como a separação acontece sem copiar nada
    ///
    /// Os dois espaços apontam para os mesmos frames. Toda página que o
    /// processo enxerga como gravável sai de gravável nos **dois lados** e
    /// ganha uma marca no descritor; o frame passa a ter dois donos.
    ///
    /// A primeira escrita, de qualquer um dos lados, vira falha de página.
    /// [`resolver_copia_na_escrita`] reconhece a marca, tira uma cópia
    /// particular do frame para quem escreveu, devolve a escrita e retoma a
    /// instrução. O processo não percebe nada além de um atraso.
    ///
    /// # Por que as três coisas precisam acontecer juntas
    ///
    /// Compartilhar o frame, tirar a escrita do filho e tirar a escrita do
    /// **pai** são uma operação só, e esquecer qualquer uma delas produz um
    /// desfecho diferente e igualmente ruim:
    ///
    /// - sem contar o dono, o primeiro dos dois a morrer devolve ao alocador
    ///   memória que o outro ainda usa;
    /// - sem tirar a escrita do filho, ele escreve direto no frame do pai;
    /// - sem tirar a escrita do **pai**, é o pai que escreve no frame do
    ///   filho — e este é o lado que se esquece, porque o pai é quem está
    ///   rodando e tudo parece funcionar até ele encostar na própria memória.
    ///
    /// # Por que as permissões são lidas de volta das tabelas
    ///
    /// Porque recriar tudo gravável destruiria o `W^X` do processo no
    /// instante em que ele tivesse um filho. O segmento de código do pai é
    /// somente leitura e executável; o do filho tem de ser a mesma coisa — e,
    /// por ser somente leitura de verdade, ele é compartilhado **sem** marca:
    /// uma escrita ali continua sendo o erro que sempre foi.
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
        //
        // As páginas de superfície ficam de fora: são os pixels de uma camada
        // do compositor, e a camada é de quem a criou. Levá-las ao filho como
        // cópia na escrita seria pior que não levar: a primeira escrita do
        // **pai** depois do `fork` tiraria uma cópia particular, e o pai
        // passaria a desenhar numa memória que o compositor não lê mais — a
        // janela congelaria sem erro nenhum.
        let mut paginas = alloc::vec::Vec::new();
        arch::sem_interrupcoes(|| {
            // SAFETY: a raiz é nossa e é válida; as interrupções mascaradas
            // garantem que ninguém altera as tabelas durante o percurso.
            unsafe {
                arch::percorrer_paginas_do_usuario(origem, privada, &mut |pagina| {
                    if !pagina.compartilhada {
                        paginas.push(pagina);
                    }
                });
            }
        });

        // # Por que a troca **inteira** vive numa seção crítica
        //
        // Porque durante ela o espaço ativo não pertence a ninguém. Todo outro
        // lugar do kernel que instala um espaço o faz depois de entregá-lo ao
        // fio — e é isso que torna a preempção inofensiva ali: ao voltar, o
        // escalonador reinstala o espaço registrado, que é o certo.
        //
        // Aqui não há a quem entregar: o espaço novo ainda vai ser do filho,
        // que não existe. Uma preempção no meio faria o escalonador
        // reinstalar o espaço **do pai** ao devolver a CPU, e o resto dos
        // mapeamentos iria para lá.
        //
        // Isso não chega a acontecer hoje, e vale ser exato sobre o porquê:
        // o único chamador é `fork`, que roda dentro de uma chamada de
        // sistema, e chamadas de sistema já entram com as interrupções
        // mascaradas — por `SFMASK` no x86 e pela própria entrada de exceção
        // no ARM. A correção vinha do chamador, não daqui.
        //
        // Depender disso é que era frágil: a condição não estava escrita em
        // lugar nenhum, e o primeiro chamador vindo de contexto de fio — um
        // `spawn` iniciado pelo kernel, por exemplo — a quebraria sem aviso.
        // Mascarar aqui torna a função correta sozinha, e o custo é zero
        // quando já se está mascarado.
        arch::sem_interrupcoes(|| {
            // SAFETY: as duas raízes carregam as entradas de topo do kernel,
            // então o código e a pilha deste fio seguem mapeados dos dois
            // lados. A troca de volta acontece em qualquer desfecho, inclusive
            // no de erro.
            unsafe {
                arch::trocar_espaco(novo.raiz);
                let r = adotar_no_espaco_ativo(&paginas);
                arch::trocar_espaco(origem);
                r?;
            }

            // O lado do pai vem **depois** de o filho estar inteiro, e a
            // ordem é deliberada: se a montagem do filho falhasse no meio, o
            // pai já estaria com metade das páginas restritas sem ninguém com
            // quem compartilhá-las. Não seria incorreto — a resolução devolve
            // a escrita sem copiar quando há um dono só —, mas seria trabalho
            // silencioso pago por um `fork` que nem aconteceu.
            //
            // Ele fica **dentro** da mesma seção crítica por um motivo mais
            // simples que o da troca de espaços: `marcar_copia_na_escrita`
            // opera sobre o espaço ativo, e manter as interrupções mascaradas
            // até o fim é mais barato do que provar, a cada leitura deste
            // código, que o escalonador reinstalaria o espaço certo ao
            // devolver a CPU.
            marcar_o_lado_do_pai(&paginas)
        })?;

        COMPARTILHADAS.fetch_add(paginas.len() as u64, Ordering::Relaxed);
        Ok(novo)
    }
}

/// Tira a escrita das páginas do pai, agora que o filho divide os frames.
///
/// Chegar a um erro aqui é ficar com o pai gravável sobre um frame que o
/// filho também alcança: as escritas do pai apareceriam na memória do filho.
/// Não há desfecho seguro que preserve os dois, e o filho é quem ainda não
/// existe para ninguém — por isso o `fork` inteiro é desfeito.
fn marcar_o_lado_do_pai(paginas: &[arch::PaginaDoUsuario]) -> Result<(), &'static str> {
    for pagina in paginas {
        if !pagina.gravavel_para_o_processo() {
            continue;
        }
        if let Err(motivo) = arch::marcar_copia_na_escrita(pagina.virtual_) {
            crate::log_error!(
                "mmu",
                "pai nao ficou protegido em {:#x}: {}",
                pagina.virtual_,
                motivo
            );
            return Err(motivo);
        }
    }
    Ok(())
}

/// Aponta o espaço ativo para as páginas descritas, sem copiar nenhuma.
///
/// # Safety
///
/// O espaço ativo precisa ser o destino, e cada `fisico` precisa ser um frame
/// vivo — o percurso que os produziu não pode ter sido invalidado no meio.
unsafe fn adotar_no_espaco_ativo(paginas: &[arch::PaginaDoUsuario]) -> Result<(), &'static str> {
    // A precondição mais importante desta função é a que não aparece nos
    // argumentos: o espaço ativo não é o de nenhum fio, e uma troca de
    // contexto no meio disto instalaria o espaço errado por baixo dela.
    //
    // Conferir custa a leitura de um registrador por `fork` e transforma o
    // "quem chama precisa lembrar" num erro que aparece na hora. Sem isto, a
    // única evidência seria uma bifurcação que falha de vez em quando — e
    // seria preciso descobrir sozinho que a condição existia.
    if arch::interrupcoes_habilitadas() {
        return Err("copia de espaco com interrupcoes ligadas");
    }

    for pagina in paginas {
        let gravavel = pagina.gravavel_para_o_processo();

        // O filho nasce com as permissões que o **processo** enxerga, e não
        // com as que o descritor do pai carrega. Nas páginas já marcadas de
        // um `fork` anterior as duas diferem: o descritor diz somente
        // leitura, e o processo escreve nelas o tempo todo.
        //
        // Mapear gravável e marcar em seguida — em vez de mapear somente
        // leitura e marcar — não é um rodeio. É o que mantém **um único**
        // ponto decidindo quem pode virar cópia na escrita: uma página que
        // chegasse aqui somente leitura de verdade seria recusada pela marca,
        // que é exatamente a proteção que queremos. Instalar a marca à mão,
        // por fora, seria uma segunda resposta para a mesma pergunta — e a
        // que não recusa nada.
        //
        // O intervalo em que a página do filho fica gravável não é
        // observável: este espaço ainda não é de nenhum fio, e as
        // interrupções estão mascaradas.
        let permissoes = Permissoes {
            escrita: gravavel,
            ..pagina.permissoes
        };

        // O dono é anotado **antes** do mapeamento, e não depois, porque o
        // caminho de erro de cada ordem é diferente: anotar antes e falhar
        // deixa um dono a mais, que a linha seguinte desfaz; mapear antes e
        // falhar ao anotar deixaria uma página mapeada sem dono registrado,
        // que ninguém desfaz — e o frame voltaria ao alocador com dois
        // espaços apontando para ele.
        if !crate::frames::compartilhar(pagina.fisico) {
            return Err("frame nao pode ser compartilhado");
        }

        // SAFETY: o frame pertence ao espaço de origem e acaba de ganhar um
        // segundo dono registrado, então ele não volta ao alocador enquanto
        // este mapeamento existir. Este é o caso que o contrato de
        // `mapear_frame` deixa ao chamador, e a contagem de donos é o que o
        // satisfaz.
        if let Err(motivo) =
            unsafe { arch::mapear_frame(pagina.virtual_, pagina.fisico, permissoes) }
        {
            crate::frames::soltar(pagina.fisico);
            return Err(motivo);
        }

        if gravavel {
            arch::marcar_copia_na_escrita(pagina.virtual_)?;
        }
    }
    Ok(())
}

/// Resolve uma falha de escrita numa página de cópia na escrita.
///
/// Devolve `false` quando a página não estava marcada — e aí a falha é o que
/// sempre foi, uma escrita proibida, que quem chamou trata como tal.
///
/// # Por que o caso de um dono só não copia
///
/// Porque não há de quem separar. É o que acontece com todo processo que
/// bifurca e cujo filho morre: as páginas continuam marcadas, e a primeira
/// escrita em cada uma delas só precisa desfazer a marca. Copiar ali seria
/// alocar um frame, copiar 4 KiB e devolver o original — trabalho cujo
/// resultado é bit a bit o estado inicial.
///
/// É também o que torna o `fork` barato de verdade no caso comum: bifurcar
/// e sair custa uma passada de marcação, e não um espaço de endereços
/// inteiro copiado duas vezes.
pub fn resolver_copia_na_escrita(endereco: u64) -> bool {
    // A marca só existe em memória de processo, e esta função é alcançada
    // pelo tratador de falha de página com **o endereço que o hardware
    // acusou** — qualquer um. Recusar fora da faixa do usuário é o que
    // mantém o caminho de resolução estreito: o kernel pode resolver cópia
    // na escrita porque ele escreve no buffer do processo, e não para que
    // uma falha em qualquer página vire uma tentativa de torná-la gravável.
    if !(crate::usuario::BASE..crate::usuario::TETO).contains(&endereco) {
        return false;
    }

    let pagina = endereco & !(TAMANHO_PAGINA - 1);

    // A seção crítica cobre da leitura do descritor ao remapeamento porque no
    // meio dela a página fica **sem tradução nenhuma**: uma preempção ali
    // devolveria a CPU a um processo cuja memória sumiu de baixo dele. E se o
    // fio que entrasse fosse o outro dono deste frame, ele resolveria a
    // própria falha sobre uma contagem de donos que estamos no meio de mudar.
    //
    // # O outro dono, em outro núcleo
    //
    // Com vários núcleos, a máscara não impede o caso de que ela protegia: o
    // outro dono pode estar resolvendo a falha dele **ao mesmo tempo**, em
    // outro núcleo. Isso continua certo, e não por sorte. Cada leitura e
    // cada mudança da contagem é atômica sob a trava do alocador, e a ordem
    // de cada lado é sempre a mesma: ler a contagem, copiar, trocar a própria
    // tradução, e só então soltar `antigo`. Então:
    //
    // - os dois leem dois donos: os dois copiam de `antigo`, que ninguém
    //   escreve — ele só fica gravável para quem o vê com um dono só —, e o
    //   segundo a soltar o devolve;
    // - um lê um dono só: o outro já soltou, e soltar vem depois de ele ter
    //   deixado de traduzir para `antigo`. Ninguém mais o alcança, e quem
    //   ficou pode torná-lo gravável sem copiar.
    //
    // A contagem só sobe por um `fork` de um dos donos, e quem bifurca é o
    // fio do processo — um só por processo —, que não está, ao mesmo tempo,
    // aqui. O caso da suíte "smp: copia na escrita em dois nucleos" faz os
    // dois donos escreverem juntos.
    arch::sem_interrupcoes(|| {
        let Some((antigo, permissoes)) = arch::copia_na_escrita_em(pagina) else {
            return false;
        };

        let restauradas = Permissoes {
            escrita: true,
            ..permissoes
        };

        let sozinho = crate::frames::donos(antigo) <= 1;
        let destino = if sozinho {
            antigo
        } else {
            let Some(novo) = crate::frames::alocar() else {
                crate::log_error!(
                    "mmu",
                    "sem frame para separar a pagina {:#x} de {} donos",
                    pagina,
                    crate::frames::donos(antigo)
                );
                return false;
            };
            // SAFETY: os dois frames são alcançáveis pelo mapa da memória
            // física, têm 4 KiB e são distintos — `novo` saiu do alocador, que
            // só entrega frames livres, e `antigo` está mapeado.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    arch::acesso_fisico(antigo),
                    arch::acesso_fisico(novo),
                    TAMANHO_PAGINA as usize,
                );
            }
            novo
        };

        // Os dois desfechos de erro abaixo precisam desfazer coisas
        // diferentes, e tratá-los juntos vazaria um frame num deles.
        //
        // Falhar em **desmapear** deixa tudo como estava: a página segue
        // apontando para `antigo`, que continua tendo os donos que tinha.
        // Só a cópia recém-tirada sobra, e é só ela que volta ao alocador —
        // devolver `antigo` aqui seria entregar memória que ainda está
        // mapeada.
        let saiu = match arch::desmapear(pagina) {
            Ok(frame) => frame,
            Err(motivo) => {
                crate::log_error!("mmu", "copia na escrita em {:#x}: {}", pagina, motivo);
                if !sozinho {
                    crate::frames::liberar(destino);
                }
                return false;
            }
        };

        // O frame que saiu tem de ser o mesmo que lemos do descritor. Entre
        // as duas leituras não há janela — as interrupções estão mascaradas,
        // e as tabelas deste espaço só mudam pelo fio dele, que é este; outro
        // núcleo não as escreve —, então divergir significa que a tabela
        // mudou por baixo de nós, e que o conteúdo copiado acima não é o
        // desta página.
        //
        // Seguir em frente aqui seria a pior variante do erro: escreveríamos
        // uma cópia do frame errado no endereço certo, e o processo passaria
        // a ler dados de outro lugar sem nenhuma falha. Desistir deixa a
        // página desmapeada, o que o chamador trata como a falha que é.
        if saiu != antigo {
            crate::log_error!(
                "mmu",
                "copia na escrita em {:#x}: o descritor dizia {:#x} e saiu {:#x}",
                pagina,
                antigo,
                saiu
            );
            if !sozinho {
                crate::frames::liberar(destino);
            }
            return false;
        }

        // SAFETY: ou o frame acabou de sair do alocador, ou é o que acabou de
        // sair deste mesmo endereço virtual e tem um dono só — as duas formas
        // do invariante que `mapear_frame` exige.
        if let Err(motivo) = unsafe { arch::mapear_frame(pagina, destino, restauradas) } {
            crate::log_error!("mmu", "copia na escrita em {:#x}: {}", pagina, motivo);

            // Falhar em **mapear** é o oposto: a página já saiu das tabelas,
            // e agora os dois frames estão órfãos. `destino` não é alcançado
            // por ninguém, e a participação deste espaço em `antigo` acabou
            // junto com o mapeamento que a representava.
            //
            // Quando são o mesmo frame — o caso de um dono só — a primeira
            // linha já o devolve, e a segunda não roda. Esquecê-la no caso
            // compartilhado deixaria um dono anotado para sempre, e o frame
            // nunca mais voltaria ao alocador.
            crate::frames::liberar(destino);
            if !sozinho {
                crate::frames::soltar(antigo);
            }
            return false;
        }

        if !sozinho {
            // Agora, e não antes: até o remapeamento acima, este espaço ainda
            // apontava para `antigo`. Soltá-lo cedo o devolveria ao alocador
            // no instante em que ele fosse o último dono, e a cópia acima
            // teria lido de um frame já reciclado.
            crate::frames::soltar(antigo);
            COPIADAS.fetch_add(1, Ordering::Relaxed);
        }

        RESOLVIDAS.fetch_add(1, Ordering::Relaxed);
        true
    })
}

/// Páginas que um `fork` passou a compartilhar.
static COMPARTILHADAS: AtomicU64 = AtomicU64::new(0);
/// Falhas de escrita que a marca de cópia na escrita explicou.
static RESOLVIDAS: AtomicU64 = AtomicU64::new(0);
/// Quantas dessas exigiram de fato tirar uma cópia do frame.
///
/// A diferença entre esta e [`RESOLVIDAS`] é o que a cópia na escrita
/// economizou: uma resolução sem cópia é um frame de 4 KiB que não foi
/// alocado nem preenchido.
static COPIADAS: AtomicU64 = AtomicU64::new(0);

/// `(páginas compartilhadas, falhas resolvidas, cópias tiradas)`.
pub fn estatisticas_de_copia_na_escrita() -> (u64, u64, u64) {
    (
        COMPARTILHADAS.load(Ordering::Relaxed),
        RESOLVIDAS.load(Ordering::Relaxed),
        COPIADAS.load(Ordering::Relaxed),
    )
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
