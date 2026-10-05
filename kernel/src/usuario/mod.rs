//! Userspace: código sem privilégio e as chamadas de sistema que ele faz.
//!
//! # A linha que este módulo desenha
//!
//! Até aqui todo código do kernel era igualmente poderoso: qualquer função
//! podia escrever em qualquer endereço e falar com qualquer dispositivo. Um
//! erro em qualquer lugar podia corromper tudo.
//!
//! Ring 3 (no x86) e EL0 (no ARM) mudam isso no hardware. O processo executa
//! num modo em que instruções privilegiadas simplesmente não funcionam, e só
//! alcança as páginas marcadas como dele. A única porta para o kernel é a
//! instrução de chamada de sistema — `syscall` num, `svc` no outro.
//!
//! O ganho não é só de segurança. É de **diagnóstico**: um processo que tente
//! algo indevido gera uma falha localizada, com endereço e causa, em vez de
//! corromper silenciosamente uma estrutura do kernel.
//!
//! # A regra que vale para todo argumento
//!
//! Tudo que chega numa chamada de sistema veio de código sem privilégio, e
//! portanto **não é confiável**. Um ponteiro pode apontar para dentro do
//! kernel; um comprimento pode ser absurdo; os dois juntos podem transbordar.
//!
//! O kernel não desreferencia nada antes de [`validar_faixa`] confirmar que a
//! faixa inteira está na metade do usuário e mapeada. É a checagem que separa
//! um sistema operacional de uma biblioteca com etapas extras.
//!
//! # O que já existe, e o que ainda não
//!
//! Cada processo tem o próprio espaço de endereços, com as entradas de topo do
//! kernel copiadas e a do usuário só dele; `bifurcar` o duplica com cópia na
//! escrita, `executar` troca a imagem, `esperar` colhe o filho, e `mapear`
//! dá memória nova ao processo. São onze chamadas de sistema, listadas em
//! [`numero`].
//!
//! Os processos rodam em qualquer núcleo — um processo é um fio só, e o
//! escalonador nunca põe o mesmo fio em dois núcleos ao mesmo tempo; ver
//! [`crate::nucleos`].
//!
//! O que não existe: sinais e memória compartilhada entre processos. E não
//! existirá uma ABI de outro sistema: os programas do Duke falam a língua
//! dele — ver `docs/INTERFACE.md`, a fase 7 do roteiro.

pub mod descritores;
pub mod elf;
pub mod exemplo;
pub mod programa;

use alloc::string::String;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use politica::Permissao;

// A ABI com os programas — os números das chamadas, os erros e o mapa do
// espaço do usuário — é declarada uma vez só, no pacote que os programas
// também incluem. Ver `protocolo::usuario`.
pub use protocolo::usuario::{BASE, TETO, erro, evento, numero};

/// Onde ficam, no disco, os programas compilados à parte — os do pacote
/// `programas`, que o `xtask` põe na raiz.
///
/// Um diretório por arquitetura, porque o disco de testes é um só para as
/// duas máquinas e um executável do x86 não roda no ARM. O nome do
/// diretório é o que [`crate::arch::nome`] devolve, e a suíte confere que
/// os dois não divergiram.
///
/// É de onde o kernel lança o servidor de janelas no boot — ver
/// [`lancar_o_servidor_de_janelas`].
#[cfg(target_arch = "x86_64")]
pub const DIRETORIO_DOS_COMPILADOS: &str = "/programas/x86_64";
#[cfg(target_arch = "aarch64")]
pub const DIRETORIO_DOS_COMPILADOS: &str = "/programas/aarch64";

/// Lança o servidor de janelas, do disco.
///
/// Só com compositor: sem tela não há janela a servir. E sem o programa no
/// disco — uma máquina sem o disco dos programas —, o kernel segue sem
/// janelas, e diz por quê. A suíte não passa por aqui: ela lança o servidor
/// no caso dela, e o encerra no fim, para ele não ficar vivo nos seguintes.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn lancar_o_servidor_de_janelas() {
    if crate::grafico::relatorio().is_none() {
        crate::log_info!("janelas", "sem compositor, sem servidor de janelas");
        return;
    }
    let caminho = alloc::format!("{DIRETORIO_DOS_COMPILADOS}/janelas");
    match lancar(Some(&caminho)) {
        Ok(id) => crate::log_info!("janelas", "servidor de janelas no fio {}", id),
        Err(motivo) => crate::log_warn!(
            "janelas",
            "servidor de janelas nao lancado de {}: {}",
            caminho,
            motivo
        ),
    }
}

/// Lança o Terminal, do disco — o interpretador numa janela, ao lado do
/// servidor de janelas.
///
/// No boot, pelo kernel, como o servidor: é o que a pessoa vê ao ligar a
/// máquina. Depois, quem o lança de novo é o servidor, pelo botão da barra
/// — ver `barra::pressionar_terminal`. Nas mesmas condições do servidor, e
/// pelos mesmos motivos; a suíte o lança no caso dela.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn lancar_o_terminal() {
    if crate::grafico::relatorio().is_none() {
        return;
    }
    let caminho = alloc::format!("{DIRETORIO_DOS_COMPILADOS}/terminal");
    match lancar(Some(&caminho)) {
        Ok(id) => crate::log_info!("janelas", "terminal no fio {}", id),
        Err(motivo) => {
            crate::log_warn!("janelas", "terminal nao lancado de {}: {}", caminho, motivo)
        }
    }
}

// O espaço do usuário inteiro tem de caber numa única entrada da tabela de
// topo, e nenhuma região do kernel pode dividir essa entrada com ele.
//
// É a condição que torna possível dar uma tabela de tradução a cada processo:
// a tabela nova recebe uma cópia das entradas de topo do kernel, e as que
// sobram são do processo. Se uma entrada servisse aos dois, copiá-la levaria
// junto o mapa do processo anterior — ou, escolhendo o outro lado, deixaria o
// kernel sem heap no instante em que o processo assumisse.
//
// Conferido aqui, em tempo de compilação, porque o erro é de *aritmética de
// endereço*: mover uma constante 512 GiB para o lado não quebra nada visível
// até um processo carregar e o kernel sumir de baixo dele.
const _: () = {
    use crate::arch::entrada_de_topo;

    assert!(
        entrada_de_topo(BASE) == entrada_de_topo(TETO - 1),
        "o espaco do usuario atravessa duas entradas da tabela de topo"
    );
    assert!(
        entrada_de_topo(BASE) != entrada_de_topo(crate::heap::HEAP_INICIO as u64),
        "o heap do kernel divide a entrada de topo com o espaco do usuario"
    );
    assert!(
        entrada_de_topo(BASE) != entrada_de_topo(crate::fios::pilha::BASE),
        "as pilhas de fio dividem a entrada de topo com o espaco do usuario"
    );
};

/// Maior transferência que uma chamada aceita de uma vez, nos dois sentidos.
///
/// Um teto explícito é obrigatório: sem ele, um processo pediria uma escrita
/// de tamanho arbitrário e o kernel gastaria tempo ilimitado dentro de uma
/// chamada — negação de serviço por um número grande.
///
/// Ele vale para `ler` também, e ali o teto faz uma segunda coisa: é o que
/// limita o buffer que o kernel aloca por leitura. Sem ele, um processo
/// escolheria quanto do heap do kernel quer consumir por chamada.
const MAX_TRANSFERENCIA: u64 = 4096;

/// Maior nome de programa que `executar` aceita.
///
/// Um teto explícito porque o tamanho vem do usuário, e porque o nome é
/// copiado para a pilha do kernel **antes** de a imagem ser trocada — ver
/// [`executar`] para o porquê.
const MAX_NOME: usize = 32;

static CHAMADAS: AtomicU64 = AtomicU64::new(0);
static BIFURCACOES: AtomicU64 = AtomicU64::new(0);
static TROCAS_DE_IMAGEM: AtomicU64 = AtomicU64::new(0);
static RECUSADAS: AtomicU64 = AtomicU64::new(0);
static BYTES_ESCRITOS: AtomicU64 = AtomicU64::new(0);
/// Quantas chamadas a `mapear` deram certo, e quantas páginas elas deram.
static MAPEAMENTOS: AtomicU64 = AtomicU64::new(0);
static PAGINAS_MAPEADAS: AtomicU64 = AtomicU64::new(0);

/// Código de saída do último processo encerrado, se houve algum.
///
/// `i64::MIN` marca "nenhum": um processo pode sair com qualquer valor, e
/// usar zero como sentinela confundiria "saiu com sucesso" com "não rodou".
///
/// # Por que isto não é a resposta que um processo quer
///
/// Porque é uma global, e "o último" deixou de ser uma pergunta respondível
/// quando `bifurcar` apareceu: dois filhos que saem deixam um valor só, e
/// quem perguntou não sabe de quem ele é. O caso da bifurcação contorna isso
/// lendo os dois códigos do anel de log — o que serve a um teste e não serve
/// a um programa.
///
/// A resposta por processo é [`esperar`], que guarda o código **no fio** e o
/// entrega a quem tem direito a ele. Esta global fica porque continua sendo
/// útil ao agente e à suíte: ela responde "alguma coisa saiu, e com quanto",
/// que é uma pergunta legítima de quem observa a máquina de fora.
static ULTIMA_SAIDA: AtomicI64 = AtomicI64::new(i64::MIN);

/// Quantos processos já encerraram.
///
/// Passou a ser necessário quando `bifurcar` apareceu: com um processo só,
/// "houve saída" e "a saída foi esta" eram a mesma pergunta. Com dois, quem
/// espera precisa saber **quantas** já aconteceram antes de olhar qualquer
/// coisa.
static SAIDAS: AtomicU64 = AtomicU64::new(0);

/// Confere que `[inicio, inicio + tamanho)` está inteiramente na faixa do
/// usuário.
///
/// # Por que a soma é conferida
///
/// Porque os dois números vêm do usuário. `inicio + tamanho` com valores
/// grandes transborda, e um transbordo silencioso produziria uma faixa que
/// *parece* pequena e válida enquanto aponta para qualquer lugar.
///
/// `checked_add` transforma o ataque num erro comum — e num erro, e não num
/// número. Saturar também impediria o transbordo, mas devolveria uma faixa
/// que continua parecendo legítima; recusar diz o que aconteceu.
pub fn validar_faixa(inicio: u64, tamanho: u64) -> Result<(), i64> {
    if tamanho == 0 {
        return Ok(());
    }
    if tamanho > MAX_TRANSFERENCIA {
        return Err(erro::TAMANHO_INVALIDO);
    }
    let fim = inicio.checked_add(tamanho).ok_or(erro::ENDERECO_INVALIDO)?;
    if inicio < BASE || fim > TETO {
        return Err(erro::ENDERECO_INVALIDO);
    }

    // Estar na faixa não basta: a página pode não estar mapeada. Conferimos
    // página a página, porque uma faixa pode atravessar a fronteira entre uma
    // mapeada e outra que não.
    let mut endereco = inicio & !(crate::arch::TAMANHO_PAGINA - 1);
    while endereco < fim {
        if crate::arch::traduzir(endereco).is_none() {
            return Err(erro::ENDERECO_INVALIDO);
        }
        endereco += crate::arch::TAMANHO_PAGINA;
    }
    Ok(())
}

/// Como [`validar_faixa`], e a faixa inteira precisa ser **gravável** pelo
/// processo.
///
/// # Por que mapeada não basta
///
/// Porque o kernel escreve nela, pelo anel zero, com a proteção de escrita
/// do processador ligada. Uma página de código é do processo e está
/// mapeada — passa por [`validar_faixa`] — e é só de leitura: a escrita do
/// kernel falhava ali, a falha era do **kernel**, e era fatal. Qualquer
/// processo derrubava a máquina com um `ler` para o endereço de uma função.
/// Medido com o programa `ponteiros`: `FALHA FATAL #1: page_fault`, com o
/// endereço acusado dentro do código dele.
///
/// Uma página de cópia na escrita conta como gravável, e é de propósito: o
/// processo pode escrever nela, e a escrita do kernel é resolvida pelo
/// tratador de falha como a dele seria — ver `resolver_copia_na_escrita`.
pub fn validar_escrita(inicio: u64, tamanho: u64) -> Result<(), i64> {
    validar_faixa(inicio, tamanho)?;
    if tamanho == 0 {
        return Ok(());
    }
    let fim = inicio + tamanho;
    let mut endereco = inicio & !(crate::arch::TAMANHO_PAGINA - 1);
    while endereco < fim {
        if !crate::arch::gravavel_pelo_usuario(endereco) {
            return Err(erro::ENDERECO_INVALIDO);
        }
        endereco += crate::arch::TAMANHO_PAGINA;
    }
    Ok(())
}

/// Atende uma chamada de sistema. Chamado pelo backend de arquitetura.
/// # Safety
///
/// `quadro` precisa apontar para o quadro de usuário desta chamada, montado
/// pelo backend de arquitetura. `bifurcar` e `executar` o leem e o reescrevem.
pub unsafe fn despachar(
    numero: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    quadro: *mut core::ffi::c_void,
) -> i64 {
    CHAMADAS.fetch_add(1, Ordering::Relaxed);

    match numero {
        numero::SAIR => sair(a0 as i64),
        numero::ESCREVER => escrever(a0, a1, a2),
        numero::ID => crate::fios::id_atual() as i64,
        numero::CEDER => {
            crate::fios::ceder();
            0
        }
        numero::ABRIR => abrir(a0, a1),
        numero::LER => ler(a0, a1, a2),
        numero::FECHAR => fechar(a0),
        numero::ESPERAR => esperar(a0, a1),
        numero::MAPEAR => mapear(a0, a1),
        numero::ESCUTAR => escutar(a0, a1),
        numero::SUPERFICIE => superficie(a0, a1),
        numero::CONTROLAR => controlar(a0, a1, a2),
        numero::DESCREVER => descrever(a0, a1, a2),
        numero::TERMINAL => terminal(a0),
        numero::VALOR => valor(a0, a1, a2),
        numero::PEDIR => crate::nativo::pedir(a0, a1),
        numero::RESPOSTA => crate::nativo::resposta(a0, a1),
        // SAFETY: o quadro é o desta chamada, garantido por quem nos chamou.
        numero::BIFURCAR => unsafe { bifurcar(quadro) },
        numero::EXECUTAR => unsafe { executar(quadro, a0, a1) },
        _ => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::NUMERO_INVALIDO
        }
    }
}

/// O maior pedido que `mapear` atende de uma vez: 16 MiB.
///
/// Não é cota — uma cota por processo é trabalho da fase de consentimento, e
/// sem ela um processo pode pedir de 16 em 16 até o fim da memória, e ouvir
/// [`erro::SEM_MEMORIA`]. É teto de **latência**: a chamada roda com as
/// interrupções mascaradas, e zerar 4096 páginas de uma vez já é o bastante
/// para um tique do relógio esperar.
pub const MAIOR_MAPEAMENTO: u64 = 16 * 1024 * 1024;

/// Confere uma faixa que o processo quer ocupar com memória nova: alinhada,
/// dentro de [`protocolo::usuario::MAPEAVEL`], e livre. Os mesmos erros para
/// `mapear` e para `superficie`, porque a pergunta é a mesma.
fn conferir_faixa_livre(endereco: u64, tamanho: u64) -> Result<(), i64> {
    use crate::arch::TAMANHO_PAGINA;
    let (inicio, fim) = protocolo::usuario::MAPEAVEL;

    if !endereco.is_multiple_of(TAMANHO_PAGINA) {
        return Err(erro::ENDERECO_INVALIDO);
    }
    // A soma vem do usuário: conferida antes de comparar.
    let Some(ate) = endereco.checked_add(tamanho) else {
        return Err(erro::ENDERECO_INVALIDO);
    };
    if endereco < inicio || ate > fim {
        return Err(erro::ENDERECO_INVALIDO);
    }
    let paginas = tamanho.div_ceil(TAMANHO_PAGINA);
    if (0..paginas).any(|i| crate::arch::traduzir(endereco + i * TAMANHO_PAGINA).is_some()) {
        return Err(erro::JA_MAPEADO);
    }
    Ok(())
}

/// `mapear(endereco, tamanho)`: memória nova para o processo.
///
/// # Quem escolhe o endereço, e por quê
///
/// O processo, como num `mmap` com endereço fixo. A alternativa — o kernel
/// guardar onde o monte de cada processo termina, como o `brk` — precisaria
/// de estado novo por processo, e esse estado teria de acompanhar `fork`
/// (copiado) e `exec` (zerado). Com o endereço vindo do processo, o estado
/// mora na memória dele: o `fork` o copia junto com o resto, e o `exec` o
/// joga fora junto com o resto. O que o kernel guarda é o que ele sempre
/// guardou — as tabelas de páginas.
///
/// # Tudo ou nada
///
/// A faixa inteira é conferida antes de a primeira página ser mapeada, e
/// uma falha no meio desfaz as que já foram: um erro devolvido com metade da
/// faixa mapeada deixaria o processo sem saber o que tem.
fn mapear(endereco: u64, tamanho: u64) -> i64 {
    use crate::arch::TAMANHO_PAGINA;

    if !endereco.is_multiple_of(TAMANHO_PAGINA) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::ENDERECO_INVALIDO;
    }
    if tamanho == 0 || !tamanho.is_multiple_of(TAMANHO_PAGINA) || tamanho > MAIOR_MAPEAMENTO {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    }
    match conferir_faixa_livre(endereco, tamanho) {
        Ok(()) => {}
        Err(erro::JA_MAPEADO) => return erro::JA_MAPEADO,
        Err(e) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return e;
        }
    }

    let paginas = tamanho / TAMANHO_PAGINA;

    for i in 0..paginas {
        let pagina = endereco + i * TAMANHO_PAGINA;
        if crate::paginacao::mapear_novo(pagina, crate::arch::Permissoes::DADOS_USUARIO).is_err() {
            for j in 0..i {
                let _ = crate::paginacao::desmapear_e_liberar(endereco + j * TAMANHO_PAGINA);
            }
            return erro::SEM_MEMORIA;
        }
    }

    MAPEAMENTOS.fetch_add(1, Ordering::Relaxed);
    PAGINAS_MAPEADAS.fetch_add(paginas, Ordering::Relaxed);
    0
}

/// `sair(codigo)`.
///
/// Marca o fio como encerrado e **retorna**, em vez de trocar de contexto aqui
/// mesmo. A troca é trabalho do backend de arquitetura, que faz isso logo
/// depois — ver [`crate::fios::marcar_terminado`] para o porquê: no ARM esta
/// função roda dentro de um handler de exceção, e ceder de lá aninharia uma
/// exceção sobre a outra.
fn sair(codigo: i64) -> i64 {
    ULTIMA_SAIDA.store(codigo, Ordering::SeqCst);
    SAIDAS.fetch_add(1, Ordering::SeqCst);
    crate::log_info!("usuario", "processo encerrou com codigo {}", codigo);
    // O código vai junto: é `marcar_terminado` quem o guarda no fio e quem
    // acorda o pai, e os dois precisam acontecer na mesma seção crítica.
    // `ULTIMA_SAIDA` acima continua existindo, mas é uma global — com dois
    // processos saindo ela guarda o último, e "o último" não é pergunta que
    // alguém queira fazer. Quem quer saber de um processo específico usa
    // `esperar`.
    crate::fios::marcar_terminado(Some(codigo));
    codigo
}

/// `escrever(descritor, ptr, tamanho)`: bytes do usuário para onde o
/// descritor apontar.
///
/// # Por que existe um descritor se só há um destino possível
///
/// Porque o argumento faz parte da ABI, e a ABI é a única coisa aqui que não
/// se corrige depois: mudá-la quebra todo programa de usuário já escrito. O
/// destino é o que pode crescer sem quebrar ninguém — um arquivo, um socket,
/// outro processo —, e é justamente isso que a indireção protege.
fn escrever(descritor: u64, ponteiro: u64, tamanho: u64) -> i64 {
    // O descritor primeiro, antes de olhar o ponteiro. A ordem importa: um
    // processo que varra endereços com um descritor inválido não deve
    // conseguir distinguir "não mapeado" de "mapeado" pela resposta.
    //
    // # Por que a tabela é consultada, e não uma constante
    //
    // Porque a tabela é do processo e muda: um descritor aberto por `abrir`
    // não existia quando o programa começou, e um fechado por `fechar` deixou
    // de existir. Antes desta etapa havia um `static` de três posições, e ele
    // dava a resposta certa por não haver nenhuma outra possível.
    let nivel = match crate::fios::com_descritores(|t| t.alvo(descritor)).flatten() {
        Some(descritores::Alvo::Terminal { chave }) => {
            return escrever_no_terminal(chave, ponteiro, tamanho);
        }
        Some(descritores::Alvo::Registro) => crate::log::Level::Info,
        Some(descritores::Alvo::Diagnostico) => crate::log::Level::Error,
        // Um arquivo não recebe escrita neste kernel, e um número que não
        // está na tabela não recebe nada. As duas respostas são a mesma de
        // propósito: um processo que sondasse descritores alheios não deve
        // aprender, pelo motivo, qual deles existe.
        Some(
            descritores::Alvo::Arquivo { .. }
            | descritores::Alvo::Eventos { .. }
            | descritores::Alvo::Superficie { .. },
        )
        | None => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::DESCRITOR_INVALIDO;
        }
    };

    if let Err(e) = validar_faixa(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    if tamanho == 0 {
        return 0;
    }

    // SAFETY: `validar_faixa` confirmou que a faixa inteira está na metade do
    // usuário e mapeada. Lemos como bytes, então não há alinhamento a
    // respeitar nem interpretação a errar.
    let bytes = unsafe { core::slice::from_raw_parts(ponteiro as *const u8, tamanho as usize) };

    // Texto do usuário não é confiável nem como UTF-8. Substituir em vez de
    // recusar mantém a chamada útil para quem escreve bytes crus.
    let texto = core::str::from_utf8(bytes).unwrap_or("<bytes nao-utf8>");
    let legivel = texto.len() == tamanho as usize;

    // Chamada direta em vez de macro porque o número de volta importa: o
    // registro cabe 160 bytes e esta chamada aceita até 4096. Devolver o
    // tamanho pedido depois de guardar menos é dizer ao programa que escreveu
    // o que não escreveu — e programa nenhum tem como desconfiar.
    //
    // Uma escrita curta é a resposta certa, e é o que todo `write` faz: quem
    // chamou repete com o resto. Aqui isso produz um registro por pedaço, que
    // é o desfecho útil — nada se perde e cada pedaço fica datado.
    let guardados = crate::log::registrar(nivel, "usuario", format_args!("{}", texto));

    // Quando o texto não era UTF-8 o que foi ao registro é um marcador, não o
    // texto: aí o que se consumiu foi o buffer inteiro, e o tamanho pedido é a
    // resposta honesta.
    let aceitos = if legivel {
        guardados.min(tamanho as usize) as u64
    } else {
        tamanho
    };

    BYTES_ESCRITOS.fetch_add(aceitos, Ordering::Relaxed);
    aceitos as i64
}

/// Maior caminho que `abrir` aceita.
///
/// O nome é copiado para a pilha do kernel, e a pilha de um fio tem tamanho
/// fixo. Um teto explícito é o que impede um processo de escolher quanto da
/// pilha do kernel ele quer ocupar.
const MAX_CAMINHO: usize = 128;

static ABERTURAS: AtomicU64 = AtomicU64::new(0);
static LEITURAS: AtomicU64 = AtomicU64::new(0);
static BYTES_LIDOS: AtomicU64 = AtomicU64::new(0);

/// Copia um caminho do espaço do usuário para a pilha do kernel.
///
/// Devolve o buffer e quantos bytes valem, porque devolver uma `&str` que
/// aponta para dentro do buffer exigiria que o buffer sobrevivesse — e ele é
/// local de quem chamou.
fn copiar_caminho(ponteiro: u64, tamanho: u64) -> Result<([u8; MAX_CAMINHO], usize), i64> {
    if tamanho == 0 || tamanho as usize > MAX_CAMINHO {
        return Err(erro::TAMANHO_INVALIDO);
    }
    validar_faixa(ponteiro, tamanho)?;

    let mut buffer = [0u8; MAX_CAMINHO];
    let tamanho = tamanho as usize;
    // SAFETY: `validar_faixa` confirmou que a faixa está no espaço do usuário
    // e mapeada, e ainda estamos no espaço de endereços em que ela vale.
    unsafe {
        core::ptr::copy_nonoverlapping(ponteiro as *const u8, buffer.as_mut_ptr(), tamanho);
    }
    Ok((buffer, tamanho))
}

/// `abrir(ptr, tamanho)`: abre um arquivo e devolve o descritor dele.
///
/// # Por que o caminho é resolvido aqui e o vnode guardado
///
/// Porque é isso que um descritor **é**: o resultado de uma resolução de nome
/// feita uma vez. Guardar o caminho e resolvê-lo a cada leitura daria outra
/// coisa — um nome que pode passar a apontar para outro arquivo entre duas
/// leituras —, e é justamente a diferença que o Unix tem desde sempre.
fn abrir(ponteiro: u64, tamanho: u64) -> i64 {
    let (buffer, tamanho) = match copiar_caminho(ponteiro, tamanho) {
        Ok(par) => par,
        Err(e) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return e;
        }
    };

    let Ok(caminho) = core::str::from_utf8(&buffer[..tamanho]) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NAO_ENCONTRADO;
    };

    // Antes de resolver: um processo que um agente lançou abre o que o papel
    // do agente lê, e nada mais. Decidir antes de olhar o disco também não
    // conta a quem foi recusado se o caminho existe.
    if !crate::autorizacao::autorizar_processo(Permissao::FsRead, caminho, "fs.open").permite() {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NEGADO;
    }

    let vnode = match crate::vfs::resolver(caminho) {
        Ok(vnode) => vnode,
        Err(_) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::NAO_ENCONTRADO;
        }
    };
    if vnode.no.tipo != crate::vfs::Tipo::Arquivo {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NAO_EH_ARQUIVO;
    }

    match crate::fios::com_descritores(|t| t.abrir(vnode)) {
        Some(Some(fd)) => {
            ABERTURAS.fetch_add(1, Ordering::Relaxed);
            fd as i64
        }
        // A tabela do processo está cheia, ou não há fio atual. A segunda não
        // acontece numa chamada de sistema — ela exige um processo, e um
        // processo exige um fio.
        _ => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::SEM_DESCRITOR
        }
    }
}

/// `ler(descritor, ptr, tamanho)`: bytes de onde o descritor apontar.
///
/// # Os três tempos, e por que eles não podem virar um
///
/// O alvo sai da tabela com a trava do escalonador na mão; a leitura acontece
/// **fora** dela; a posição é avançada com a trava de novo. Ler lá dentro
/// pararia o escalonador pelo tempo de uma ida ao disco — com as interrupções
/// desligadas, e portanto sem nem o relógio andando.
///
/// O preço dos três tempos é uma janela: entre pegar o alvo e avançar a
/// posição, outro fio poderia mexer no mesmo descritor. Não pode acontecer
/// hoje — a tabela é do processo e um processo tem um fio só —, e no dia em
/// que um processo tiver dois, é aqui que a corrida mora.
fn ler(descritor: u64, ponteiro: u64, tamanho: u64) -> i64 {
    // O descritor primeiro, antes de olhar o ponteiro — a mesma ordem de
    // `escrever`, e pelo mesmo motivo: um processo que varra endereços com um
    // descritor inválido não deve distinguir "mapeado" de "não mapeado" pela
    // resposta.
    let Some(Some(alvo)) = crate::fios::com_descritores(|t| t.alvo(descritor)) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    if let descritores::Alvo::Eventos { chave } = alvo {
        return ler_eventos(chave, ponteiro, tamanho);
    }
    if let descritores::Alvo::Terminal { chave } = alvo {
        return ler_do_terminal(chave, ponteiro, tamanho);
    }
    let descritores::Alvo::Arquivo { vnode, posicao } = alvo else {
        // Os destinos de log não leem. Devolver zero fingiria um arquivo
        // vazio, e um programa que leia até o fim entenderia isso como "o
        // arquivo acabou" em vez de "este descritor não é de leitura".
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };

    if let Err(e) = validar_escrita(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    if tamanho == 0 {
        return 0;
    }

    // Os bytes passam por um buffer do kernel antes de chegar ao usuário.
    //
    // Escrever direto no ponteiro do usuário pareceria mais barato e seria
    // errado: a leitura pode levar milissegundos no disco, e o relógio
    // preempta o fio no meio dela. Quando ele voltar, o espaço de endereços
    // ativo é outro — e a escrita teria ido para a memória de outro processo,
    // no mesmo endereço.
    let mut buffer = alloc::vec![0u8; tamanho as usize];
    let lidos = match crate::vfs::ler_em(&vnode, posicao, &mut buffer) {
        Ok(lidos) => lidos,
        Err(motivo) => {
            crate::log_warn!("usuario", "ler falhou: {}", motivo.motivo());
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::ENDERECO_INVALIDO;
        }
    };

    if lidos > 0 {
        // SAFETY: `validar_faixa` confirmou que a faixa inteira está no
        // espaço do usuário e mapeada, e `lidos` não passa de `tamanho`.
        // Estamos no espaço de endereços em que ela vale: a preempção durante
        // a leitura acima devolve o fio ao mesmo espaço antes de continuar.
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), ponteiro as *mut u8, lidos);
        }
    }

    crate::fios::com_descritores(|t| t.avancar(descritor, lidos as u64));
    LEITURAS.fetch_add(1, Ordering::Relaxed);
    BYTES_LIDOS.fetch_add(lidos as u64, Ordering::Relaxed);
    lidos as i64
}

/// Quantos eventos uma leitura entrega, no máximo.
///
/// Eles passam por um buffer na pilha do kernel antes de ir ao processo —
/// ver [`ler_eventos`] —, e dezesseis são 512 bytes. Um programa que queira
/// mais lê de novo; a fila não perde nada entre uma leitura e outra.
const EVENTOS_POR_LEITURA: usize = 16;

/// `escutar(ptr, tamanho)`: torna o processo o ouvinte do canal de eventos
/// com o nome dado, e devolve um descritor para ler dele.
fn escutar(ponteiro: u64, tamanho: u64) -> i64 {
    if tamanho == 0 || tamanho as usize > crate::eventos::NOME_MAX {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    }
    if let Err(e) = validar_faixa(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    let mut nome = [0u8; crate::eventos::NOME_MAX];
    // SAFETY: `validar_faixa` confirmou a faixa no espaço do usuário e
    // mapeada, e estamos no espaço do processo que chamou; o tamanho cabe no
    // buffer pela conferência acima.
    unsafe {
        core::ptr::copy_nonoverlapping(ponteiro as *const u8, nome.as_mut_ptr(), tamanho as usize);
    }
    let ouvinte = crate::fios::id_atual();
    let chave = match crate::eventos::escutar(&nome[..tamanho as usize], ouvinte) {
        Ok(chave) => chave,
        Err(crate::eventos::Recusa::NomeInvalido) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::TAMANHO_INVALIDO;
        }
        Err(crate::eventos::Recusa::Ocupado) => return erro::OCUPADO,
    };
    match crate::fios::com_descritores(|t| t.instalar(descritores::Alvo::Eventos { chave })) {
        Some(Some(descritor)) => descritor as i64,
        // Sem vaga na tabela, o canal aberto agora não teria como ser lido
        // por ninguém: ele é largado antes de a recusa voltar.
        _ => {
            crate::eventos::largar(chave, ouvinte);
            erro::SEM_DESCRITOR
        }
    }
}

/// `superficie(tamanho, endereco)`: uma camada do compositor, com os pixels
/// mapeados no processo — ver [`protocolo::usuario::numero::SUPERFICIE`] e
/// [`crate::superficies`].
///
/// A ordem das conferências é a de `mapear`: primeiro o que se sabe sem
/// tocar em nada — o tamanho, a faixa —, depois a criação, e o descritor por
/// último. Sem vaga de descritor, a superfície recém-criada é desfeita: um
/// processo não pode ficar com uma camada que ele não tem como controlar
/// nem fechar.
fn superficie(tamanho: u64, endereco: u64) -> i64 {
    let (largura, altura) = protocolo::usuario::superficie::de_tamanho(tamanho);
    let Some(bytes) = crate::superficies::bytes_de(largura, altura) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    };
    match conferir_faixa_livre(endereco, bytes) {
        Ok(()) => {}
        Err(erro::JA_MAPEADO) => return erro::JA_MAPEADO,
        Err(e) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return e;
        }
    }

    let dono = crate::fios::id_atual();
    let chave = match crate::superficies::criar(dono, largura, altura, endereco) {
        Ok(chave) => chave,
        Err(crate::superficies::Recusa::SemTela) => return erro::SEM_TELA,
        Err(crate::superficies::Recusa::Tamanho) => return erro::TAMANHO_INVALIDO,
        Err(_) => return erro::SEM_MEMORIA,
    };
    match crate::fios::com_descritores(|t| t.instalar(descritores::Alvo::Superficie { chave })) {
        Some(Some(descritor)) => descritor as i64,
        _ => {
            crate::superficies::largar(chave, dono);
            erro::SEM_DESCRITOR
        }
    }
}

/// `controlar(descritor, operacao, argumento)`: mexe na camada de uma
/// superfície.
fn controlar(descritor: u64, op: u64, argumento: u64) -> i64 {
    let Some(Some(descritores::Alvo::Superficie { chave })) =
        crate::fios::com_descritores(|t| t.alvo(descritor))
    else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    let dono = crate::fios::id_atual();
    let feito = if op == protocolo::usuario::superficie::operacao::ENTRADA {
        // O argumento é um descritor, e tem de ser de um canal que este
        // processo escuta: apontar a entrada de uma janela para o canal de
        // outro processo seria mandar a ele o que a pessoa digita aqui.
        match crate::fios::com_descritores(|t| t.alvo(argumento)) {
            Some(Some(descritores::Alvo::Eventos { chave: canal }))
                if crate::eventos::e_ouvinte(canal, dono) =>
            {
                crate::superficies::definir_entrada(chave, dono, canal)
            }
            _ => Err(crate::superficies::Recusa::Argumento),
        }
    } else {
        crate::superficies::controlar(chave, dono, op, argumento)
    };
    match feito {
        Ok(()) => 0,
        Err(crate::superficies::Recusa::Argumento) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::ARGUMENTO_INVALIDO
        }
        // O filho que herdou o descritor: para ele, este descritor não
        // aponta para nada que seja dele.
        Err(_) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

/// `descrever(descritor, ptr, tamanho)`: o que a janela de uma superfície é,
/// para a árvore semântica — ver [`protocolo::usuario::descricao`].
fn descrever(descritor: u64, ponteiro: u64, tamanho: u64) -> i64 {
    let Some(Some(descritores::Alvo::Superficie { chave })) =
        crate::fios::com_descritores(|t| t.alvo(descritor))
    else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    if tamanho == 0 || tamanho as usize > protocolo::usuario::descricao::MAIOR {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    }
    if let Err(e) = validar_faixa(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    let mut copia = alloc::vec![0u8; tamanho as usize];
    // SAFETY: `validar_faixa` confirmou a faixa no espaço do usuário e
    // mapeada, e estamos no espaço do processo que chamou; a cópia tem o
    // tamanho dela.
    unsafe {
        core::ptr::copy_nonoverlapping(ponteiro as *const u8, copia.as_mut_ptr(), copia.len());
    }
    let Ok(texto) = core::str::from_utf8(&copia) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::ARGUMENTO_INVALIDO;
    };
    match crate::superficies::descrever(chave, crate::fios::id_atual(), texto) {
        Ok(()) => 0,
        Err(crate::superficies::Recusa::Argumento) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::ARGUMENTO_INVALIDO
        }
        Err(_) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

/// Quantos bytes uma leitura ou escrita do pseudo-terminal move, no máximo.
///
/// Passam por um buffer na pilha do kernel, pelo motivo de [`ler_eventos`]. O
/// resto fica para a próxima chamada — as duas direções aceitam uma resposta
/// parcial.
const BYTES_DO_TERMINAL: usize = 512;

/// `terminal(canal)`: abre o pseudo-terminal, com os avisos de saída no
/// canal de eventos do descritor `canal`.
///
/// O canal tem de ser um que este processo escuta: o aviso vai para quem
/// ouve o canal, e um processo que apontasse o canal de outro faria o kernel
/// acordar um processo alheio a cada linha impressa.
fn terminal(canal: u64) -> i64 {
    // O pseudo-terminal é a linha de comando da pessoa: o que se digita nele
    // o interpretador executa como ela. Prender-se a ele é `terminal.attach`,
    // uma permissão que a política enumera — no papel `sistema`, e em nenhum
    // dos agentes: um processo que um agente lançou não o abre, nem quando
    // ele está livre, com a janela do Terminal fechada.
    if !crate::autorizacao::autorizar_processo(Permissao::TerminalAttach, "", "terminal.attach")
        .permite()
    {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NEGADO;
    }
    let fio = crate::fios::id_atual();
    let Some(Some(descritores::Alvo::Eventos { chave: canal })) =
        crate::fios::com_descritores(|t| t.alvo(canal))
    else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    if !crate::eventos::e_ouvinte(canal, fio) {
        // O filho de um `fork` com o descritor do pai: o canal não é dele.
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    }
    let chave = match crate::pseudoterminal::abrir(fio, canal) {
        Ok(chave) => chave,
        Err(crate::pseudoterminal::Recusa::Ocupado) => return erro::OCUPADO,
    };
    match crate::fios::com_descritores(|t| t.instalar(descritores::Alvo::Terminal { chave })) {
        Some(Some(descritor)) => descritor as i64,
        _ => {
            crate::pseudoterminal::fechar(chave, fio);
            erro::SEM_DESCRITOR
        }
    }
}

/// `escrever` no pseudo-terminal: digitar no interpretador.
fn escrever_no_terminal(chave: crate::pseudoterminal::Chave, ponteiro: u64, tamanho: u64) -> i64 {
    if let Err(e) = validar_faixa(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    let n = (tamanho as usize).min(BYTES_DO_TERMINAL);
    let mut copia = [0u8; BYTES_DO_TERMINAL];
    // SAFETY: `validar_faixa` confirmou a faixa no espaço do usuário e
    // mapeada, e estamos no espaço do processo que chamou; `n` cabe nela e
    // no buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(ponteiro as *const u8, copia.as_mut_ptr(), n);
    }
    // Um caractere cortado no fim do pedaço não é texto inválido: é o começo
    // do próximo pedaço. Só o que vem antes dele é digitado agora.
    let texto = match core::str::from_utf8(&copia[..n]) {
        Ok(texto) => texto,
        Err(e) if e.error_len().is_none() && e.valid_up_to() > 0 => {
            // SAFETY: `valid_up_to` é, por contrato, onde o UTF-8 válido acaba.
            unsafe { core::str::from_utf8_unchecked(&copia[..e.valid_up_to()]) }
        }
        Err(_) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::ARGUMENTO_INVALIDO;
        }
    };
    match crate::pseudoterminal::escrever(chave, crate::fios::id_atual(), texto) {
        Some(aceitos) => aceitos as i64,
        None => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

/// `ler` no pseudo-terminal: o que o kernel imprimiu, sem bloquear.
fn ler_do_terminal(chave: crate::pseudoterminal::Chave, ponteiro: u64, tamanho: u64) -> i64 {
    let n = (tamanho as usize).min(BYTES_DO_TERMINAL);
    if let Err(e) = validar_escrita(ponteiro, n as u64) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    let mut buffer = [0u8; BYTES_DO_TERMINAL];
    let Some(lidos) = crate::pseudoterminal::ler(chave, crate::fios::id_atual(), &mut buffer[..n])
    else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    // SAFETY: `validar_escrita` confirmou os `n` bytes no espaço do usuário,
    // mapeados e graváveis, e `lidos <= n`.
    unsafe {
        core::ptr::copy_nonoverlapping(buffer.as_ptr(), ponteiro as *mut u8, lidos);
    }
    lidos as i64
}

/// `valor(descritor, ptr, tamanho)`: o texto mais antigo que um agente
/// pediu para um campo da janela da superfície — ver
/// [`protocolo::usuario::numero::VALOR`].
///
/// Passa por um buffer do kernel, pelo motivo de [`ler_eventos`]: a tranca
/// das superfícies não fica tomada enquanto se escreve na memória do
/// processo.
fn valor(descritor: u64, ponteiro: u64, tamanho: u64) -> i64 {
    use crate::superficies::SemValor;
    let Some(Some(descritores::Alvo::Superficie { chave })) =
        crate::fios::com_descritores(|t| t.alvo(descritor))
    else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
    };
    let n = (tamanho as usize).min(protocolo::usuario::descricao::MAIOR_TEXTO);
    if let Err(e) = validar_escrita(ponteiro, n as u64) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }
    let mut buffer = [0u8; protocolo::usuario::descricao::MAIOR_TEXTO];
    match crate::superficies::tirar_valor(chave, crate::fios::id_atual(), &mut buffer[..n]) {
        Ok(lidos) => {
            // SAFETY: `validar_escrita` confirmou os `n` bytes no espaço do
            // usuário, mapeados e graváveis, e `lidos <= n`.
            unsafe {
                core::ptr::copy_nonoverlapping(buffer.as_ptr(), ponteiro as *mut u8, lidos);
            }
            lidos as i64
        }
        Err(SemValor::Nenhum) => erro::NAO_ENCONTRADO,
        Err(SemValor::NaoCabe) => erro::TAMANHO_INVALIDO,
        Err(SemValor::NaoEhSua) => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

/// `ler` num canal de eventos: eventos inteiros, ou o fio estaciona.
///
/// # Por que passar por um buffer, se as interrupções estão mascaradas
///
/// Porque a cópia para o processo acontece **fora** da tranca dos canais, e
/// não dentro: escrever na memória do processo pode falhar numa página de
/// cópia na escrita e passar pelo tratador de falha, e isso não é coisa
/// para se fazer com a tranca de um recurso que handlers de interrupção
/// também tomam.
fn ler_eventos(chave: crate::eventos::Chave, ponteiro: u64, tamanho: u64) -> i64 {
    let tamanho_do_evento = evento::TAMANHO as u64;
    // Um buffer menor que um evento é recusado, em vez de receber metade de
    // um — o formato só funciona se o leitor sempre souber onde um evento
    // começa.
    if tamanho < tamanho_do_evento {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    }
    let cabem = ((tamanho / tamanho_do_evento) as usize).min(EVENTOS_POR_LEITURA);
    if let Err(e) = validar_escrita(ponteiro, cabem as u64 * tamanho_do_evento) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }

    let mut eventos = [evento::Evento::default(); EVENTOS_POR_LEITURA];
    match crate::eventos::colher(chave, crate::fios::id_atual(), &mut eventos[..cabem]) {
        crate::eventos::Colheita::Entregues(n) => {
            for (i, e) in eventos[..n].iter().enumerate() {
                let bytes = e.em_bytes();
                // SAFETY: `validar_escrita` confirmou os `cabem` eventos no
                // espaço do usuário, mapeados e graváveis, e `i < n <= cabem`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        (ponteiro + i as u64 * tamanho_do_evento) as *mut u8,
                        bytes.len(),
                    );
                }
            }
            (n as u64 * tamanho_do_evento) as i64
        }
        // O fio foi estacionado. O backend de arquitetura reexecuta a
        // chamada quando ele acordar; o valor daqui não chega a ninguém.
        crate::eventos::Colheita::Estacionado => 0,
        crate::eventos::Colheita::NaoEhSeu => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

/// `fechar(descritor)`: devolve a vaga à tabela do processo.
fn fechar(descritor: u64) -> i64 {
    // Um canal de eventos é largado antes da vaga: o nome fica livre para o
    // próximo ouvinte na hora, e não quando alguém tropeçar no ouvinte morto.
    //
    // Uma superfície, pelo mesmo motivo: a camada sai da tela quando o
    // processo fecha, e não quando ele morrer.
    match crate::fios::com_descritores(|t| t.alvo(descritor)) {
        Some(Some(descritores::Alvo::Eventos { chave })) => {
            crate::eventos::largar(chave, crate::fios::id_atual());
        }
        Some(Some(descritores::Alvo::Superficie { chave })) => {
            crate::superficies::largar(chave, crate::fios::id_atual());
        }
        Some(Some(descritores::Alvo::Terminal { chave })) => {
            crate::pseudoterminal::fechar(chave, crate::fios::id_atual());
        }
        _ => {}
    }
    match crate::fios::com_descritores(|t| t.fechar(descritor)) {
        Some(true) => 0,
        _ => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::DESCRITOR_INVALIDO
        }
    }
}

// O desfecho que `esperar` escreve é ABI, e mora com o resto dela — ver
// `protocolo::usuario::BYTES_DO_DESFECHO`.
pub use protocolo::usuario::{BYTES_DO_DESFECHO, desfecho};

/// `esperar(id, ponteiro)`: colhe um filho que terminou.
///
/// Devolve o identificador do filho colhido, e escreve o código de saída
/// dele no ponteiro quando ele não é nulo.
///
/// # Por que esta chamada precisa poder ser reexecutada
///
/// Porque ela é a única que bloqueia, e bloquear no ARM não é possível de
/// onde ela roda. Uma chamada de sistema ali acontece **dentro de um handler
/// de exceção**, e trocar de fio no meio dela abandonaria a pilha de kernel
/// em que o handler está — quando o fio voltasse, ele retomaria pelo quadro
/// da exceção, e não de dentro desta função. As linhas depois do bloqueio
/// nunca rodariam.
///
/// A saída é não bloquear aqui dentro. Quando não há filho para colher,
/// [`crate::fios::colher_filho`] marca o fio como
/// [`Estado::Esperando`](crate::fios::Estado) e esta função **retorna**; o
/// backend de arquitetura vê que o fio parou, o estaciona, e quando ele
/// acorda **chama a chamada de novo**, com os mesmos argumentos. A segunda
/// passagem acha o filho e devolve o resultado de verdade.
///
/// É o que um sistema operacional chama de chamada reiniciável, e o preço é
/// um invariante: `esperar` não pode ter efeito nenhum no caminho em que
/// devolve "ainda não". Ela não tem — só lê a tabela e marca o próprio fio.
///
/// O valor devolvido nesse caminho não chega a usuário nenhum: o backend o
/// descarta e reexecuta. Devolvemos zero por ser o mais inofensivo se um dia
/// alguém esquecer de descartá-lo.
fn esperar(alvo: u64, ponteiro: u64) -> i64 {
    // O ponteiro é conferido **antes** da colheita, e a ordem não é estilo.
    //
    // Colher é destrutivo: marca o filho como colhido e libera o zumbi para o
    // coletor. Conferindo depois, um ponteiro ruim recusaria a chamada com o
    // filho já consumido — o código de saída dele deixaria de existir, e a
    // segunda tentativa do processo ouviria que não há mais filho nenhum. Um
    // argumento inválido custaria a resposta em vez de custar a chamada.
    //
    // Medido: com a conferência depois da colheita, o caso do paciente
    // reprova — ele pede de propósito uma espera com o endereço 1 antes da
    // legítima, e do outro lado não acha mais o filho.
    if ponteiro != 0
        && let Err(erro) = validar_escrita(ponteiro, BYTES_DO_DESFECHO)
    {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro;
    }

    match crate::fios::colher_filho((alvo != 0).then_some(alvo)) {
        crate::fios::Colheita::Colhido(id, saida) => {
            if ponteiro != 0 {
                // O código **e** se ele vale. Ver [`BYTES_DO_DESFECHO`] para
                // por que a segunda palavra não é opcional.
                let (codigo, valeu) = match saida {
                    Some(codigo) => (codigo, desfecho::SAIU),
                    None => (0, desfecho::MORTO),
                };

                // SAFETY: `validar_faixa` conferiu acima que os dezesseis
                // bytes estão na faixa do usuário e mapeados, e estamos no
                // espaço de endereços do processo que chamou.
                //
                // Sem alinhamento garantido: o ponteiro vem do usuário, e um
                // `write` comum de `i64` num endereço ímpar é comportamento
                // indefinido no x86 e falha de alinhamento no ARM.
                unsafe {
                    let destino = ponteiro as *mut i64;
                    destino.write_unaligned(codigo);
                    destino.add(1).write_unaligned(valeu);
                }
            }
            id as i64
        }
        // O fio já saiu da lista do escalonador — quem o tirou foi a própria
        // colheita, na mesma seção crítica em que viu que não havia o que
        // colher. Esta chamada será reexecutada quando ele voltar; ver o
        // cabeçalho, e `fios::colher_filho` para o porquê de não haver aqui
        // uma segunda chamada marcando o estado.
        crate::fios::Colheita::Aguardando => 0,
        crate::fios::Colheita::SemFilhos => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::SEM_FILHOS
        }
    }
}

/// `bifurcar()`: duplica o processo.
///
/// O filho recebe uma cópia do espaço de endereços e acorda retornando `0`
/// desta mesma chamada; o pai recebe o identificador do fio do filho.
///
/// # Safety
///
/// `quadro` precisa ser o quadro de usuário desta chamada.
unsafe fn bifurcar(quadro: *mut core::ffi::c_void) -> i64 {
    // O filho herda a autoridade, e conta na cota do papel dela.
    let autoridade = crate::fios::autoridade_atual();
    let Ok(cota) = crate::autorizacao::permitir_processo(autoridade, "process.fork") else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NEGADO;
    };
    let espaco = match crate::paginacao::Espaco::clonar_o_ativo(programa::ENTRADA_PRIVADA) {
        Ok(espaco) => espaco,
        Err(motivo) => {
            crate::log_warn!("usuario", "bifurcar falhou: {}", motivo);
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::SEM_MEMORIA;
        }
    };

    // SAFETY: o quadro é o desta chamada e o espaço é cópia do ativo, que é o
    // do fio que chamou — exatamente o que `bifurcar` exige.
    match unsafe { crate::fios::bifurcar("usuario", quadro as *const _, espaco, cota) } {
        Ok(id) => {
            BIFURCACOES.fetch_add(1, Ordering::Relaxed);
            id.numero() as i64
        }
        Err(crate::fios::COTA_ESGOTADA) => {
            crate::autorizacao::recusar_pela_cota(autoridade, "process.fork", cota);
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::NEGADO
        }
        Err(motivo) => {
            crate::log_warn!("usuario", "bifurcar falhou: {}", motivo);
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::SEM_VAGA_DE_FIO
        }
    }
}

/// `executar(ptr, tamanho)`: troca a imagem deste processo por outra.
///
/// Em caso de sucesso não retorna para quem chamou — retorna para o primeiro
/// endereço do programa novo, porque o quadro da chamada foi reescrito.
///
/// # O detalhe que não pode ser invertido
///
/// O nome é copiado para a pilha do kernel **antes** de a imagem ser trocada.
/// `programa::carregar` instala um espaço de endereços novo, e no instante em
/// que isso acontece o ponteiro do usuário deixa de significar qualquer coisa:
/// ele apontava para memória que já não está mapeada. Ler depois seria ler o
/// programa novo achando que é o nome.
///
/// # Safety
///
/// `quadro` precisa ser o quadro de usuário desta chamada.
unsafe fn executar(quadro: *mut core::ffi::c_void, ponteiro: u64, tamanho: u64) -> i64 {
    if tamanho == 0 || tamanho as usize > MAX_NOME {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::TAMANHO_INVALIDO;
    }
    if let Err(e) = validar_faixa(ponteiro, tamanho) {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return e;
    }

    let mut buffer = [0u8; MAX_NOME];
    let tamanho = tamanho as usize;
    // SAFETY: `validar_faixa` confirmou que a faixa está no espaço do usuário
    // e mapeada, e ainda estamos no espaço de endereços em que ela vale.
    unsafe {
        core::ptr::copy_nonoverlapping(ponteiro as *const u8, buffer.as_mut_ptr(), tamanho);
    }

    let Ok(nome) = core::str::from_utf8(&buffer[..tamanho]) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::PROGRAMA_DESCONHECIDO;
    };
    // O programa vem do sistema de arquivos, e não mais de uma busca numa
    // tabela estática. A tabela continua existindo — ela é o que
    // `/bin` serve —, mas quem a consulta agora é o VFS, e trocá-la pelo
    // Btrfs não muda nenhuma linha daqui. É a promessa que o README fazia
    // desde que `executar` existe.
    //
    // Um nome sem barra é procurado em `/bin`, que é o caminho de busca
    // inteiro deste kernel. Um nome absoluto é usado como veio, o que já
    // permite executar qualquer coisa que esteja montada.
    let caminho = if nome.starts_with('/') {
        alloc::string::String::from(nome)
    } else {
        alloc::format!("{}/{}", crate::vfs::DIRETORIO_DOS_PROGRAMAS, nome)
    };

    // A decisão é sobre o caminho já resolvido: um nome sem barra vira o de
    // `/bin`, e é esse que a política confere.
    if !crate::autorizacao::autorizar_processo(Permissao::ProcessRun, &caminho, "process.exec")
        .permite()
    {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::NEGADO;
    }

    let imagem = match crate::vfs::ler_tudo(&caminho) {
        Ok(bytes) => bytes,
        Err(motivo) => {
            crate::log_warn!(
                "usuario",
                "executar: `{}` nao pode ser lido: {}",
                caminho,
                motivo.motivo()
            );
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::PROGRAMA_DESCONHECIDO;
        }
    };

    let novo = match programa::carregar(&imagem) {
        Ok(programa) => programa,

        // Falhou antes do ponto de não retorno: o processo que chamou está
        // inteiro — a imagem dele mapeada, a pilha no lugar — e devolver um
        // erro é o que um `execve` faz quando recusa o arquivo.
        //
        // Esta distinção não existia, e o tratamento era o do pior caso para
        // os dois: qualquer falha matava o processo. Uma imagem malformada ou
        // uma falta momentânea de memória em `Espaco::novo`, as duas
        // recuperáveis, custavam o processo inteiro por uma premissa — "sem a
        // anterior" — que só vale do outro lado da troca.
        Err(programa::Falha::ProcessoIntacto(motivo)) => {
            crate::log_warn!("usuario", "executar recusado: {}", motivo);
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return erro::SEM_MEMORIA;
        }

        // Aqui sim: sem imagem e sem a anterior, não há para onde voltar.
        // Encerrar é o único desfecho honesto, e é o que um `execve` que falha
        // depois do ponto de não retorno faz em qualquer sistema.
        Err(programa::Falha::SemVolta(motivo)) => {
            crate::log_error!("usuario", "executar falhou depois de trocar: {}", motivo);
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            return sair(erro::SEM_MEMORIA);
        }
    };

    crate::log_info!("usuario", "processo trocou de imagem para `{}`", nome);
    TROCAS_DE_IMAGEM.fetch_add(1, Ordering::Relaxed);

    // SAFETY: o quadro é o desta chamada, e entrada e pilha acabaram de ser
    // mapeadas com permissão de usuário no espaço que agora está ativo.
    unsafe { crate::arch::redirecionar_para(quadro, novo.entrada(), novo.topo_da_pilha()) };
    0
}

/// Lança um programa no anel sem privilégio, num fio próprio.
///
/// Sem caminho, lança o exemplo embutido. Com caminho, lê a imagem do VFS —
/// que é o que permite rodar um programa **do disco** pelo canal do agente ou
/// pelo interpretador, sem que ele precise estar embutido no kernel.
///
/// Devolve o identificador do fio. Não espera o processo terminar: quem chama
/// é o canal do agente, e bloquear ali travaria o atendimento — o resultado
/// aparece depois em `user.stats`.
///
/// # Como o caminho chega ao fio novo
///
/// Num ponteiro, e não numa variável global. [`crate::fios::criar`] carrega um
/// `u64` até a função de entrada, e é nele que vai a `String` vazada de
/// propósito — o fio a reconstrói e a larga. Zero significa "o exemplo".
///
/// Uma global exigiria decidir o que acontece quando dois lançamentos se
/// cruzam: ou uma trava segurando o segundo, ou o segundo sobrescrevendo o
/// caminho do primeiro antes de ele ler. O ponteiro não tem essa pergunta,
/// porque cada fio recebe o dele.
pub fn lancar(caminho: Option<&str>) -> Result<u64, &'static str> {
    lancar_como(caminho, crate::autorizacao::Autoridade::Sistema)
}

/// Como [`lancar`], com a autoridade de quem pediu: um processo que um
/// agente lança age como o agente — ver [`crate::fios::criar_como`].
pub fn lancar_como(
    caminho: Option<&str>,
    autoridade: crate::autorizacao::Autoridade,
) -> Result<u64, &'static str> {
    extern "C" fn hospedar(argumento: u64) -> ! {
        let imagem = if argumento == 0 {
            alloc::borrow::Cow::Borrowed(exemplo::bytes())
        } else {
            // SAFETY: o ponteiro veio do `Box::into_raw` logo abaixo, este fio
            // é o único que o recebeu, e ele o reconstrói uma vez só.
            let caminho = unsafe { alloc::boxed::Box::from_raw(argumento as *mut String) };
            match crate::vfs::ler_tudo(&caminho) {
                Ok(bytes) => alloc::borrow::Cow::Owned(bytes),
                Err(motivo) => {
                    crate::log_error!(
                        "usuario",
                        "nao foi possivel ler `{}`: {}",
                        caminho,
                        motivo.motivo()
                    );
                    crate::fios::terminar()
                }
            }
        };

        // Carregar e entrar em dois passos, com a imagem largada no meio: ver
        // `programa::entrar` sobre o vazamento que isto fecha.
        let carregado = programa::carregar(&imagem);
        drop(imagem);
        match carregado.and_then(programa::entrar) {
            Ok(_) => unreachable!("entrar nao retorna em caso de sucesso"),
            Err(falha) => {
                crate::log_error!(
                    "usuario",
                    "nao foi possivel entrar em userspace: {}",
                    falha.motivo()
                );
                crate::fios::terminar()
            }
        }
    }

    limpar_ultima_saida();

    // A cota de processos do papel de quem lança: contada antes de nascer,
    // e de novo ao nascer — ver `fios::criar_processo`.
    let Ok(cota) = crate::autorizacao::permitir_processo(autoridade, "process.run") else {
        return Err(crate::fios::COTA_ESGOTADA);
    };

    let argumento = match caminho {
        None => 0,
        Some(caminho) => {
            alloc::boxed::Box::into_raw(alloc::boxed::Box::new(String::from(caminho))) as u64
        }
    };

    match crate::fios::criar_processo("usuario", hospedar, argumento, autoridade, cota) {
        Ok(id) => Ok(id.numero()),
        Err(motivo) => {
            if motivo == crate::fios::COTA_ESGOTADA {
                crate::autorizacao::recusar_pela_cota(autoridade, "process.run", cota);
            }
            // O fio não nasceu, então ninguém vai reconstruir a caixa. Largá-la
            // aqui é obrigatório: sem isto, cada lançamento recusado — e eles
            // acontecem, o escalonador tem dezesseis vagas — deixaria uma
            // `String` no heap para sempre.
            if argumento != 0 {
                // SAFETY: o ponteiro veio do `into_raw` acima e não foi
                // entregue a ninguém, porque `criar` falhou.
                drop(unsafe { alloc::boxed::Box::from_raw(argumento as *mut String) });
            }
            Err(motivo)
        }
    }
}

/// `(chamadas, recusadas, bytes escritos)`.
pub fn estatisticas() -> (u64, u64, u64) {
    (
        CHAMADAS.load(Ordering::Relaxed),
        RECUSADAS.load(Ordering::Relaxed),
        BYTES_ESCRITOS.load(Ordering::Relaxed),
    )
}

/// `(mapeamentos, páginas mapeadas)`: o que `mapear` deu, desde o boot.
pub fn estatisticas_de_memoria() -> (u64, u64) {
    (
        MAPEAMENTOS.load(Ordering::Relaxed),
        PAGINAS_MAPEADAS.load(Ordering::Relaxed),
    )
}

/// `(aberturas, leituras, bytes lidos)`.
pub fn estatisticas_de_arquivo() -> (u64, u64, u64) {
    (
        ABERTURAS.load(Ordering::Relaxed),
        LEITURAS.load(Ordering::Relaxed),
        BYTES_LIDOS.load(Ordering::Relaxed),
    )
}

/// `(bifurcacoes, trocas de imagem, saidas)`.
pub fn estatisticas_de_processo() -> (u64, u64, u64) {
    (
        BIFURCACOES.load(Ordering::Relaxed),
        TROCAS_DE_IMAGEM.load(Ordering::Relaxed),
        SAIDAS.load(Ordering::SeqCst),
    )
}

/// O código de saída do último processo encerrado, se houve algum.
pub fn ultima_saida() -> Option<i64> {
    match ULTIMA_SAIDA.load(Ordering::SeqCst) {
        i64::MIN => None,
        codigo => Some(codigo),
    }
}

/// Esquece o último código de saída, para que um novo possa ser observado.
pub fn limpar_ultima_saida() {
    ULTIMA_SAIDA.store(i64::MIN, Ordering::SeqCst);
}
