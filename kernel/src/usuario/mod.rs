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
    /// `escrever(ptr, tamanho)`: manda bytes para o log do kernel.
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
pub fn despachar(numero: u64, a0: u64, a1: u64, _a2: u64) -> i64 {
    CHAMADAS.fetch_add(1, Ordering::Relaxed);

    match numero {
        numero::SAIR => sair(a0 as i64),
        numero::ESCREVER => escrever(a0, a1),
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

/// `escrever(ptr, tamanho)`: bytes do usuário para o log do kernel.
fn escrever(ponteiro: u64, tamanho: u64) -> i64 {
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
    crate::log_info!("usuario", "{}", texto);

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
