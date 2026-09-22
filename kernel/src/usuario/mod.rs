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
//! # O que ainda não existe
//!
//! Processos ainda compartilham o espaço de endereços do kernel — separá-los
//! exige uma tabela de tradução por processo, que é o passo seguinte. O que já
//! existe é a separação de *privilégio*: o processo não alcança as páginas do
//! kernel, porque elas não têm o bit de usuário.

pub mod elf;
pub mod exemplo;
pub mod programa;

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Números das chamadas de sistema.
///
/// Iguais nas duas arquiteturas: o que muda é o registrador que carrega cada
/// coisa, e isso é detalhe do backend.
pub mod numero {
    /// `sair(codigo)`: encerra o processo. Não retorna.
    pub const SAIR: u64 = 0;
    /// `escrever(descritor, ptr, tamanho)`: manda bytes para onde o
    /// descritor apontar.
    pub const ESCREVER: u64 = 1;
    /// `id()`: devolve o identificador do fio que executa o processo.
    pub const ID: u64 = 2;
    /// `ceder()`: devolve a CPU voluntariamente.
    pub const CEDER: u64 = 3;
}

/// Erros devolvidos ao usuário, sempre negativos.
///
/// Negativo porque o valor de retorno é um `i64` e as chamadas que dão certo
/// devolvem zero ou uma contagem. É a convenção do Linux, e existe porque
/// distingue erro de resultado sem precisar de um segundo canal.
pub mod erro {
    pub const NUMERO_INVALIDO: i64 = -1;
    pub const ENDERECO_INVALIDO: i64 = -2;
    pub const TAMANHO_INVALIDO: i64 = -3;
    pub const DESCRITOR_INVALIDO: i64 = -4;
}

/// Os descritores que todo processo recebe abertos.
///
/// Os números são os do Unix, e isso é deliberado: não porque o Duke pretenda
/// ser POSIX, mas porque qualquer pessoa que já escreveu um programa sabe de
/// cor o que 1 e 2 significam. Inventar uma numeração própria cobraria esse
/// conhecimento de volta sem devolver nada.
pub mod descritor {
    /// Leitura. Reservado: ainda não há de onde ler, e **escrever nele é
    /// erro** — é o caso que prova que a tabela é consultada de verdade.
    pub const ENTRADA: u64 = 0;
    /// Saída comum. Vai para o log do kernel em nível `info`.
    pub const SAIDA: u64 = 1;
    /// Saída de erro. Vai para o mesmo log em nível `error`.
    pub const ERRO: u64 = 2;
}

/// Para onde um descritor aponta.
///
/// Hoje só há dois destinos, os dois no log do kernel. O tipo existe mesmo
/// assim porque é ele que torna a indireção real: sem ele, `escrever` voltaria
/// a ter um único destino embutido e o descritor seria decoração.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Alvo {
    /// Log do kernel, nível `info`.
    Registro,
    /// Log do kernel, nível `error`.
    Diagnostico,
}

/// A tabela de descritores.
///
/// # Por que ela é `static` e imutável
///
/// Porque nada pode alterá-la ainda: não existe `abrir`, nem `fechar`, nem
/// herança por `fork`. Uma tabela imutável não precisa de lock, e um lock que
/// não existe não pode ser esquecido dentro de um handler.
///
/// Quando houver mais de um processo, ela vira campo do processo — e é
/// exatamente por isso que a indireção entra agora. Acrescentar o argumento
/// depois que houver programas de usuário significaria quebrar todos eles.
static TABELA: [Option<Alvo>; 3] = [None, Some(Alvo::Registro), Some(Alvo::Diagnostico)];

// A tabela é posicional, mas os nomes acima é que formam a ABI. Se alguém
// reordenar uma sem renumerar os outros, os dois deixam de concordar em
// silêncio e todo programa de usuário passa a escrever no lugar errado.
//
// Esta amarra é conferida em tempo de compilação, então o erro aparece no
// build e não num log estranho meses depois.
const _: () = {
    assert!(TABELA[descritor::ENTRADA as usize].is_none());
    assert!(TABELA[descritor::SAIDA as usize].is_some());
    assert!(TABELA[descritor::ERRO as usize].is_some());
};

/// Resolve um descritor no seu destino, se ele permitir escrita.
fn alvo_de_escrita(descritor: u64) -> Option<Alvo> {
    // `get` em vez de indexar: o número veio do usuário e pode ser qualquer
    // coisa. Indexar entraria em pânico, e um processo não deve conseguir
    // derrubar o kernel com um inteiro grande.
    TABELA
        .get(usize::try_from(descritor).ok()?)
        .copied()
        .flatten()
}

/// Onde o espaço do usuário começa e termina.
///
/// Uma faixa baixa e modesta, bem longe do heap (64 GiB), das pilhas de fio
/// (128 GiB) e do kernel. No x86 o kernel vive na metade alta, então qualquer
/// endereço aqui é inequivocamente do usuário; no ARM o kernel está em
/// `0x4008_0000`, e por isso a faixa começa acima dos 4 GiB — não há como
/// confundir uma com a outra.
pub const BASE: u64 = 0x0000_0001_0000_0000;
/// Fim exclusivo da faixa do usuário.
pub const TETO: u64 = BASE + 0x1000_0000;

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

/// Maior escrita que uma chamada aceita de uma vez.
///
/// Um teto explícito é obrigatório: sem ele, um processo pediria uma escrita
/// de tamanho arbitrário e o kernel gastaria tempo ilimitado dentro de uma
/// chamada — negação de serviço por um número grande.
const MAX_ESCRITA: u64 = 4096;

static CHAMADAS: AtomicU64 = AtomicU64::new(0);
static RECUSADAS: AtomicU64 = AtomicU64::new(0);
static BYTES_ESCRITOS: AtomicU64 = AtomicU64::new(0);

/// Código de saída do último processo encerrado, se houve algum.
///
/// `i64::MIN` marca "nenhum": um processo pode sair com qualquer valor, e
/// usar zero como sentinela confundiria "saiu com sucesso" com "não rodou".
static ULTIMA_SAIDA: AtomicI64 = AtomicI64::new(i64::MIN);

/// Confere que `[inicio, inicio + tamanho)` está inteiramente na faixa do
/// usuário.
///
/// # Por que a aritmética é toda saturante
///
/// Porque os dois números vêm do usuário. `inicio + tamanho` com valores
/// grandes transborda, e um transbordo silencioso produziria uma faixa que
/// *parece* pequena e válida enquanto aponta para qualquer lugar. Saturar
/// transforma o ataque num erro comum.
pub fn validar_faixa(inicio: u64, tamanho: u64) -> Result<(), i64> {
    if tamanho == 0 {
        return Ok(());
    }
    if tamanho > MAX_ESCRITA {
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

/// Atende uma chamada de sistema. Chamado pelo backend de arquitetura.
pub fn despachar(numero: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    CHAMADAS.fetch_add(1, Ordering::Relaxed);

    match numero {
        numero::SAIR => sair(a0 as i64),
        numero::ESCREVER => escrever(a0, a1, a2),
        numero::ID => crate::fios::id_atual() as i64,
        numero::CEDER => {
            crate::fios::ceder();
            0
        }
        _ => {
            RECUSADAS.fetch_add(1, Ordering::Relaxed);
            erro::NUMERO_INVALIDO
        }
    }
}

/// `sair(codigo)`. Nunca retorna.
/// `sair(codigo)`.
///
/// Marca o fio como encerrado e **retorna**, em vez de trocar de contexto aqui
/// mesmo. A troca é trabalho do backend de arquitetura, que faz isso logo
/// depois — ver [`crate::fios::marcar_terminado`] para o porquê: no ARM esta
/// função roda dentro de um handler de exceção, e ceder de lá aninharia uma
/// exceção sobre a outra.
fn sair(codigo: i64) -> i64 {
    ULTIMA_SAIDA.store(codigo, Ordering::SeqCst);
    crate::log_info!("usuario", "processo encerrou com codigo {}", codigo);
    crate::fios::marcar_terminado();
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
    let Some(alvo) = alvo_de_escrita(descritor) else {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        return erro::DESCRITOR_INVALIDO;
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
    match alvo {
        Alvo::Registro => crate::log_info!("usuario", "{}", texto),
        Alvo::Diagnostico => crate::log_error!("usuario", "{}", texto),
    }

    BYTES_ESCRITOS.fetch_add(tamanho, Ordering::Relaxed);
    tamanho as i64
}

/// Lança o programa de exemplo num fio próprio.
///
/// Devolve o identificador do fio. Não espera o processo terminar: quem chama
/// é o canal do agente, e bloquear ali travaria o atendimento — o resultado
/// aparece depois em `user.stats`.
pub fn lancar_exemplo() -> Result<u64, &'static str> {
    extern "C" fn hospedar(_argumento: u64) -> ! {
        match programa::executar(exemplo::bytes()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(motivo) => {
                crate::log_error!(
                    "usuario",
                    "nao foi possivel entrar em userspace: {}",
                    motivo
                );
                crate::fios::terminar()
            }
        }
    }

    limpar_ultima_saida();
    crate::fios::criar("usuario", hospedar, 0).map(|id| id.numero())
}

/// `(chamadas, recusadas, bytes escritos)`.
pub fn estatisticas() -> (u64, u64, u64) {
    (
        CHAMADAS.load(Ordering::Relaxed),
        RECUSADAS.load(Ordering::Relaxed),
        BYTES_ESCRITOS.load(Ordering::Relaxed),
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
