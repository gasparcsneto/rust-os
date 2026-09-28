//! Alocador de frames de memória física.
//!
//! # O que é um frame
//!
//! A unidade de memória física que o hardware de paginação manipula: 4 KiB
//! alinhados. Enquanto a paginação decide *onde* a memória aparece no espaço
//! de endereçamento virtual, este módulo decide *qual* pedaço de RAM física
//! está livre para ser usado.
//!
//! É a camada mais baixa da gerência de memória. Tudo que vier depois —
//! tabelas de página, heap, pilhas de processo — pede frames daqui.
//!
//! # Por que um bitmap
//!
//! Um bit por frame: ligado significa livre. As alternativas seriam uma lista
//! encadeada de frames livres (que precisa de espaço *dentro* dos frames, e
//! portanto exige que eles estejam mapeados para serem manipulados) ou um
//! alocador que nunca libera (simples, mas inútil assim que houver processos).
//!
//! O bitmap custa 1 bit por 4 KiB, ou seja, 32 KiB para cobrir 1 GiB. É
//! estático e de tamanho fixo, o que significa que nunca falha por falta de
//! espaço para se gerenciar — propriedade que vale muito na camada mais baixa
//! do sistema.
//!
//! # O que fica de fora
//!
//! Três coisas nunca podem ser entregues:
//!
//! 1. Memória que o firmware marcou como reservada.
//! 2. A própria imagem do kernel, incluindo sua pilha.
//! 3. O frame do endereço zero, para que desreferenciar um ponteiro nulo
//!    continue falhando em vez de corromper dados de verdade.
//!
//! Quem sabe sobre (2) é cada arquitetura, e por motivos diferentes — ver
//! [`crate::arch::reservar_faixas`].

// Só a injeção de falha da suíte usa atômicos aqui.
#[cfg(feature = "modo-teste")]
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

// Toda tomada de `ALOCADOR` abaixo passa por `sem_interrupcoes`, e a partir da
// fase 1 isso deixou de ser zelo e virou requisito. Com o escalonador
// preemptivo, o timer pode trocar de fio de execução em qualquer instrução: um
// fio preemptado segurando esta trava faria o próximo que pedisse um frame
// girar para sempre, porque um spinlock não é reentrante e só o dono o solta.
// Mascarar interrupções desliga a preempção junto, que é o que torna a seção
// crítica de fato crítica.

/// Tamanho de um frame. 4 KiB é o granulado nativo das duas arquiteturas.
pub const TAMANHO_FRAME: u64 = 4096;

/// Quantos frames o bitmap rastreia: 1 GiB de cobertura.
///
/// Memória além disso é ignorada com um aviso. Preferimos um limite explícito
/// e um bitmap estático a uma estrutura dinâmica que precisaria de um alocador
/// para existir — o que seria circular, já que somos nós o alocador de base.
const MAX_FRAMES: usize = 1 << 18;

const PALAVRAS: usize = MAX_FRAMES / 64;

struct Alocador {
    /// Bit ligado = frame livre. Índice relativo a [`Alocador::base`].
    bitmap: [u64; PALAVRAS],
    /// Endereço físico correspondente ao bit 0.
    base: u64,
    /// Quantos frames estão de fato sob gerência.
    rastreados: usize,
    livres: usize,
    /// Por onde começar a próxima busca.
    ///
    /// Sem esta dica, alocar N frames seria O(N²): cada busca recomeçaria do
    /// zero e percorreria tudo que já foi entregue.
    dica: usize,
    /// Quantos donos **além do primeiro** cada frame tem.
    ///
    /// Zero é o caso comum e quer dizer "um dono", não "nenhum": um frame
    /// alocado sempre pertence a alguém. A contagem começa a subir quando a
    /// cópia na escrita faz dois espaços de endereços apontarem para o mesmo
    /// frame.
    ///
    /// # Por que um byte por frame, e não uma estrutura só para os
    /// compartilhados
    ///
    /// Um mapa esparso — hash, árvore — custaria uma alocação de heap no
    /// meio do `fork` e uma busca em cada falha de página. Este array custa
    /// 256 KiB de `.bss` e responde em uma indexação, sempre. É a mesma
    /// escolha que o bitmap acima faz, pelo mesmo motivo: a camada mais baixa
    /// da gerência de memória não pode depender das camadas de cima para
    /// existir.
    ///
    /// Um byte comporta 256 donos; o kernel comporta dezesseis fios. O teto
    /// é inalcançável e ainda assim [`compartilhar`] o confere, porque um
    /// transbordo aqui produziria um frame liberado com donos vivos — a pior
    /// falha possível nesta camada, e silenciosa.
    compartilhamentos: [u8; MAX_FRAMES],
    /// Quantos frames têm mais de um dono agora.
    ///
    /// Mantido incrementalmente porque a alternativa — varrer os 256 KiB a
    /// cada pergunta — transformaria uma consulta de diagnóstico numa
    /// varredura sob a trava do alocador.
    compartilhados: usize,
    inicializado: bool,
}

static ALOCADOR: Mutex<Alocador> = Mutex::new(Alocador {
    bitmap: [0; PALAVRAS],
    base: 0,
    rastreados: 0,
    livres: 0,
    dica: 0,
    compartilhamentos: [0; MAX_FRAMES],
    compartilhados: 0,
    inicializado: false,
});

/// Executa `f` com acesso exclusivo ao alocador.
///
/// Concentrar a tomada da trava num lugar só é o que torna a invariante
/// estrutural em vez de uma regra que cada chamador precisa lembrar: não há
/// como acessar o alocador sem passar por aqui, e aqui a preempção está
/// desligada.
fn com_alocador<R>(f: impl FnOnce(&mut Alocador) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ALOCADOR.lock()))
}

impl Alocador {
    /// Marca um frame como livre, se estiver dentro da janela rastreada.
    fn liberar_indice(&mut self, indice: usize) {
        if indice >= self.rastreados {
            return;
        }
        let palavra = indice / 64;
        let bit = 1u64 << (indice % 64);
        if self.bitmap[palavra] & bit == 0 {
            self.bitmap[palavra] |= bit;
            self.livres += 1;
            // Um frame que volta à circulação não tem mais dono nenhum, e a
            // contagem precisa acompanhar. Zerá-la **aqui** — no único ponto
            // por onde um frame volta a ficar livre — é o que torna a
            // invariante estrutural: nenhum caminho de liberação pode
            // esquecer, porque todos passam por esta linha.
            //
            // Sem isto, um frame liberado com contagem residual voltaria ao
            // alocador, seria entregue a outro dono e a primeira resolução de
            // cópia na escrita dele acharia que há dois — não copiaria, e os
            // dois processos passariam a escrever na mesma memória.
            self.zerar_compartilhamento(indice);
        }
    }

    /// Apaga a contagem de donos extras de um frame.
    fn zerar_compartilhamento(&mut self, indice: usize) {
        if self.compartilhamentos[indice] != 0 {
            self.compartilhamentos[indice] = 0;
            self.compartilhados -= 1;
        }
    }

    /// Marca um frame como ocupado.
    fn ocupar_indice(&mut self, indice: usize) {
        if indice >= self.rastreados {
            return;
        }
        let palavra = indice / 64;
        let bit = 1u64 << (indice % 64);
        if self.bitmap[palavra] & bit != 0 {
            self.bitmap[palavra] &= !bit;
            self.livres -= 1;
        }
    }

    /// Este índice está livre?
    ///
    /// O bit e o deslocamento aparecem em quatro lugares diferentes, e a
    /// conta é do tipo que se copia errado uma vez e ninguém percebe: um `/`
    /// no lugar de um `%` responde sobre outro frame, sempre.
    fn livre(&self, indice: usize) -> bool {
        self.bitmap[indice / 64] & (1u64 << (indice % 64)) != 0
    }

    /// Converte um endereço físico no índice do frame que o contém.
    fn indice_de(&self, endereco: u64) -> Option<usize> {
        if endereco < self.base {
            return None;
        }
        let indice = ((endereco - self.base) / TAMANHO_FRAME) as usize;
        (indice < self.rastreados).then_some(indice)
    }
}

/// Descobre a memória disponível e monta o bitmap.
///
/// Chame uma vez, depois que [`crate::machine`] estiver preenchido.
/// Prepara o alocador a partir do mapa de memória da máquina.
///
/// Devolve erro quando não há nenhuma região utilizável. Não é um aviso: sem
/// frames, a paginação não tem de onde tirar tabelas, e ligar a MMU com uma
/// tabela que não mapeia nada tranca o núcleo num laço de exceções do qual
/// não se sai nem se relata. Quem chama precisa poder parar aqui.
pub fn init() -> Result<(), &'static str> {
    let mut menor = u64::MAX;
    let mut maior = 0u64;

    crate::machine::com_regioes(|regiao| {
        if regiao.tipo == crate::machine::TipoRegiao::Utilizavel {
            menor = menor.min(regiao.inicio);
            maior = maior.max(regiao.fim);
        }
    });

    if menor == u64::MAX {
        return Err("nenhuma regiao utilizavel no mapa de memoria");
    }

    let base = menor & !(TAMANHO_FRAME - 1);
    let necessarios = ((maior - base) / TAMANHO_FRAME) as usize;
    let rastreados = necessarios.min(MAX_FRAMES);

    com_alocador(|a| {
        a.base = base;
        a.rastreados = rastreados;
        a.livres = 0;
        a.dica = 0;
        // O bitmap começa todo zerado, ou seja, tudo ocupado. Liberamos
        // explicitamente só o que o firmware garantiu ser utilizável — é a
        // política segura: esquecer de liberar desperdiça memória, esquecer de
        // reservar corrompe o sistema.
        a.bitmap = [0; PALAVRAS];
        a.compartilhamentos = [0; MAX_FRAMES];
        a.compartilhados = 0;
        a.inicializado = true;
    });

    crate::machine::com_regioes(|regiao| {
        if regiao.tipo != crate::machine::TipoRegiao::Utilizavel {
            return;
        }
        // Arredondamos para dentro: um frame só é considerado livre se estiver
        // *inteiramente* dentro da região. Um frame parcialmente reservado
        // entregue como livre seria corrupção garantida.
        //
        // # Nenhum caso protege este arredondamento, e não há como escrever um
        //
        // Medido, trocando `div_ceil` por divisão comum: a suíte inteira
        // passa. Não é falha dos casos — nas duas máquinas em que este kernel
        // roda, toda região do mapa começa e termina em fronteira de página, e
        // então as duas contas dão o mesmo número. Não há mapa aqui em que a
        // diferença apareça.
        //
        // Fica porque o mapa vem do firmware e o formato não obriga
        // alinhamento nenhum: um E820 com uma região começando em 0x9FC00 —
        // que existe em hardware real, é o começo da área de dados da BIOS —
        // entregaria ao alocador um frame cuja primeira metade não é dele.
        let primeiro = regiao.inicio.div_ceil(TAMANHO_FRAME);
        let ultimo = regiao.fim / TAMANHO_FRAME;

        com_alocador(|a| {
            for frame in primeiro..ultimo {
                let endereco = frame * TAMANHO_FRAME;
                if let Some(indice) = a.indice_de(endereco) {
                    a.liberar_indice(indice);
                }
            }
        });
    });

    // Cada arquitetura sabe de coisas diferentes que não podem ser entregues.
    crate::arch::reservar_faixas(reservar);

    // O frame do endereço zero nunca é entregue, para que desreferenciar um
    // ponteiro nulo continue produzindo uma falha diagnosticável em vez de
    // corromper dados legítimos.
    //
    // # Nenhum caso protege esta linha, e não há como escrever um
    //
    // Medido, apagando-a: a suíte inteira passa. Não é falha dos casos. Nas
    // duas máquinas em que este kernel roda, o frame zero já não estaria
    // livre de qualquer forma — no x86 o mapa do firmware marca a primeira
    // página como reservada, e no ARM a RAM começa em 0x4000_0000, então o
    // índice zero nem existe. Não há máquina aqui em que a diferença apareça.
    //
    // Ela fica porque o custo é uma linha e o que ela evita é uma classe
    // inteira: um mapa que declare a primeira página utilizável entrega zero
    // como endereço de verdade, e zero é sentinela em vários lugares deste
    // kernel. A metade que **tem** caso é `liberar`, que recusa o frame zero
    // explicitamente — ali a diferença é observável, e um caso a observa.
    reservar(0, TAMANHO_FRAME);

    let (livres, total) = estatisticas();
    crate::log_info!(
        "frames",
        "{} de {} frames livres ({} MiB), base {:#x}",
        livres,
        total,
        livres as u64 * TAMANHO_FRAME / 1024 / 1024,
        base
    );

    if necessarios > MAX_FRAMES {
        crate::log_warn!(
            "frames",
            "memoria alem de {} MiB ignorada pelo bitmap",
            MAX_FRAMES as u64 * TAMANHO_FRAME / 1024 / 1024
        );
    }

    // A condição que importa é esta, e não "o mapa declarou alguma região":
    // um mapa com regiões que as reservas consumiram inteiras chega aqui com
    // zero frames e é tão inviável quanto um mapa vazio.
    if livres == 0 {
        return Err("nenhum frame livre depois das reservas");
    }

    Ok(())
}

/// Retira da circulação todos os frames que tocam a faixa `[inicio, fim)`.
///
/// Arredonda para fora de propósito: se qualquer byte de um frame estiver
/// dentro da faixa, o frame inteiro é reservado. O oposto — entregar um frame
/// parcialmente reservado — corromperia o que estivesse ali.
pub fn reservar(inicio: u64, fim: u64) {
    if fim <= inicio {
        return;
    }
    let primeiro = inicio / TAMANHO_FRAME;
    let ultimo = fim.div_ceil(TAMANHO_FRAME);

    com_alocador(|a| {
        for frame in primeiro..ultimo {
            let endereco = frame * TAMANHO_FRAME;
            if let Some(indice) = a.indice_de(endereco) {
                a.ocupar_indice(indice);
            }
        }
    });
}

/// Quantas alocações de frame devem falhar de propósito.
///
/// # Por que injetar falha, e por que só na suíte
///
/// Porque este kernel tem vários caminhos de limpeza que só rodam quando a
/// memória acaba — `mmio::mapear` desfaz os mapeamentos que já fez,
/// `clonar_o_ativo` larga o espaço pela metade, `resolver_copia_na_escrita`
/// tem desfechos distintos para cada metade que falha — e **nenhum deles é
/// exercitado**. Eles foram lidos e considerados corretos, que é o mesmo
/// nível de garantia que um comentário.
///
/// Fazer a memória acabar de verdade não serve: a máquina de teste tem 128
/// MiB e esgotá-los levaria a suíte junto. O que se quer é que a **próxima**
/// alocação falhe, no ponto exato que o caso escolheu.
///
/// Fora do modo de teste isto não existe, e `alocar` não ganha nem um
/// desvio.
#[cfg(feature = "modo-teste")]
static FALHAS_ENCOMENDADAS: AtomicUsize = AtomicUsize::new(0);

/// Faz as próximas `quantas` alocações de frame falharem.
///
/// Devolve quantas ainda estavam encomendadas de uma chamada anterior, que é
/// zero em qualquer uso correto — um caso que deixa falhas pendentes
/// contamina o seguinte.
#[cfg(feature = "modo-teste")]
pub fn encomendar_falhas(quantas: usize) -> usize {
    FALHAS_ENCOMENDADAS.swap(quantas, Ordering::SeqCst)
}

/// Quantas falhas encomendadas ainda não foram consumidas.
#[cfg(feature = "modo-teste")]
pub fn falhas_pendentes() -> usize {
    FALHAS_ENCOMENDADAS.load(Ordering::SeqCst)
}

/// Entrega um frame livre, ou `None` se a memória acabou.
///
/// O endereço devolvido é físico e alinhado em [`TAMANHO_FRAME`]. O conteúdo
/// é indefinido: quem pedir um frame para uma tabela de página precisa zerá-lo
/// antes de usar, porque lixo interpretado como descritor é caos.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn alocar() -> Option<u64> {
    // A falha encomendada vem antes de tocar no alocador: o que se quer
    // imitar é "não havia frame", e não "havia e deu errado depois".
    #[cfg(feature = "modo-teste")]
    if FALHAS_ENCOMENDADAS
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return None;
    }

    com_alocador(|a| {
        if !a.inicializado || a.livres == 0 {
            return None;
        }

        let palavras = a.rastreados.div_ceil(64);

        // Duas passadas: da dica até o fim, depois do início até a dica. Assim a
        // busca é amortizada mesmo quando a memória livre está fragmentada no
        // começo do bitmap.
        for tentativa in 0..2 {
            let (de, ate) = if tentativa == 0 {
                (a.dica, palavras)
            } else {
                (0, a.dica.min(palavras))
            };

            for palavra in de..ate {
                if a.bitmap[palavra] == 0 {
                    continue;
                }
                let bit = a.bitmap[palavra].trailing_zeros() as usize;
                let indice = palavra * 64 + bit;
                if indice >= a.rastreados {
                    continue;
                }

                a.ocupar_indice(indice);
                a.dica = palavra;
                return Some(a.base + indice as u64 * TAMANHO_FRAME);
            }
        }

        None
    })
}

/// Devolve um frame ao alocador.
///
/// Liberar um frame que não estava alocado é tratado como no-op em vez de
/// pânico: num kernel, um erro de contabilidade não deve derrubar o sistema
/// se houver como seguir com segurança.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn liberar(endereco: u64) {
    // O frame do endereço zero fica fora de circulação para sempre, e não só
    // desde a inicialização. Zero é sentinela em vários lugares — "nenhum
    // frame", ponteiro nulo —, e devolvê-lo à lista o transforma num endereço
    // que o alocador entrega de verdade. `reservar` cuidava disso uma vez, no
    // boot; bastava alguém liberá-lo depois para desfazer.
    //
    // Recusar aqui é o desfecho certo justamente porque a chamada é um
    // engano: quem libera o frame zero está devolvendo uma sentinela que leu
    // como endereço.
    if endereco < TAMANHO_FRAME {
        return;
    }

    let extras = com_alocador(|a| {
        let Some(indice) = a.indice_de(endereco) else {
            return 0;
        };
        let extras = a.compartilhamentos[indice];
        a.liberar_indice(indice);
        // Buscar a partir daqui aproveita a localidade: quem libera
        // costuma voltar a alocar logo em seguida.
        a.dica = indice / 64;
        extras
    });

    // O relato sai **fora** da trava do alocador de propósito: escrever no
    // log toma a trava da serial, e aninhar as duas na ordem errada é como
    // nascem os travamentos que só aparecem sob carga.
    //
    // A contagem já foi zerada acima, então o sistema segue coerente — o que
    // este aviso denuncia é que alguém devolveu ao alocador um frame que
    // ainda tinha dono. Para páginas compartilhadas o caminho certo é
    // [`soltar`]; chegar aqui com `extras > 0` é sempre erro de contabilidade
    // de quem chamou.
    if extras > 0 {
        crate::log_error!(
            "frames",
            "frame {:#x} liberado com {} dono(s) alem do primeiro",
            endereco,
            extras as u64 + 1
        );
    }
}

/// Anota mais um dono para um frame que já está alocado.
///
/// Devolve `false` quando o frame não está sob gerência ou quando a contagem
/// estouraria — e recusar é o desfecho certo nos dois casos, porque um dono
/// que o alocador não registra é um dono que ele vai atropelar.
///
/// É a metade de ida de [`soltar`]: quem compartilha precisa soltar, e o
/// frame só volta à circulação quando o último o soltar.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn compartilhar(endereco: u64) -> bool {
    if endereco < TAMANHO_FRAME {
        return false;
    }

    com_alocador(|a| {
        let Some(indice) = a.indice_de(endereco) else {
            return false;
        };

        // Compartilhar um frame **livre** é o pedido mais perigoso que esta
        // função pode receber: o alocador o entregaria a outro dono logo em
        // seguida, e a contagem faria os dois se acharem sócios de algo que
        // um deles nem pediu. É engano de quem chama, sempre.
        if a.livre(indice) {
            return false;
        }

        let Some(agora) = a.compartilhamentos[indice].checked_add(1) else {
            return false;
        };
        if a.compartilhamentos[indice] == 0 {
            a.compartilhados += 1;
        }
        a.compartilhamentos[indice] = agora;
        true
    })
}

/// Retira um dono do frame, devolvendo-o ao alocador se era o último.
///
/// Devolve `true` quando o frame voltou de fato à circulação.
///
/// # Por que não é só `liberar`
///
/// Porque com cópia na escrita um frame pertence a vários espaços de
/// endereços ao mesmo tempo, e quem desmonta um deles não sabe quantos
/// outros ainda existem. `liberar` responde "o dono acabou"; esta responde
/// "**um** dono acabou", que é a única pergunta que um espaço de endereços
/// consegue responder sozinho.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn soltar(endereco: u64) -> bool {
    if endereco < TAMANHO_FRAME {
        return false;
    }

    let ultimo = com_alocador(|a| match a.indice_de(endereco) {
        // Fora da janela rastreada não há contagem nem circulação, e
        // `liberar` também trata este caso como no-op. Responder "voltou"
        // seria inventar um retorno para uma operação que não aconteceu.
        None => false,
        // Já estava livre: soltar de novo é engano de contabilidade de quem
        // chamou, e nada volta porque nada estava fora.
        Some(indice) if a.livre(indice) => false,
        Some(indice) if a.compartilhamentos[indice] > 0 => {
            a.compartilhamentos[indice] -= 1;
            if a.compartilhamentos[indice] == 0 {
                a.compartilhados -= 1;
            }
            false
        }
        // Sem donos extras, soltar é liberar.
        Some(_) => true,
    });

    if ultimo {
        liberar(endereco);
    }
    ultimo
}

/// Quantos donos este frame tem.
///
/// Um frame alocado e não compartilhado responde `1`. Zero quando ele não
/// está sob gerência **ou está livre** — as duas respostas honestas para
/// "quem é dono disto?" quando ninguém é. Responder `1` para um frame livre
/// seria pior que não responder: quem decide se pode escrever numa página
/// pelo número de donos concluiria que tem exclusividade sobre memória que o
/// alocador está prestes a entregar a outro.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn donos(endereco: u64) -> u32 {
    com_alocador(|a| match a.indice_de(endereco) {
        Some(indice) if !a.livre(indice) => a.compartilhamentos[indice] as u32 + 1,
        _ => 0,
    })
}

/// Quantos frames têm mais de um dono agora.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn compartilhados() -> usize {
    com_alocador(|a| a.compartilhados)
}

/// `(frames livres, frames rastreados)`.
pub fn estatisticas() -> (usize, usize) {
    com_alocador(|a| (a.livres, a.rastreados))
}

/// Endereço físico coberto pelo primeiro frame rastreado.
pub fn base() -> u64 {
    com_alocador(|a| a.base)
}

/// O frame que contém este endereço está livre?
///
/// Existe para os testes: permite verificar que faixas reservadas — a imagem
/// do kernel, o frame nulo — realmente não estão na circulação.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn esta_livre(endereco: u64) -> bool {
    com_alocador(|a| match a.indice_de(endereco) {
        Some(indice) => a.livre(indice),
        None => false,
    })
}

/// Destrava o alocador de frames à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ALOCADOR.force_unlock() };
}
