//! A ABI entre o kernel e os programas de usuário.
//!
//! # Por que ela mora aqui
//!
//! Pelo mesmo motivo do resto deste pacote. Enquanto os programas de usuário
//! eram montados à mão no próprio kernel, os números das chamadas de sistema
//! tinham um lado só. Com programas compilados à parte — o pacote
//! `programas` —, eles passaram a ter dois, e dois lados com a mesma lista
//! escrita duas vezes são duas listas que podem divergir: um número trocado
//! não dá erro de compilação, dá um programa que pede para ler e escreve.
//!
//! Aqui estão os números, os erros e o mapa do espaço do usuário. O kernel e
//! os programas incluem este módulo, e nenhum dos dois declara nada disso.

/// Números das chamadas de sistema.
///
/// Iguais nas duas arquiteturas: o que muda é o registrador que carrega cada
/// coisa, e isso é detalhe do backend. No x86, `rax` traz o número e `rdi`,
/// `rsi` e `rdx` os argumentos; no ARM, `x8` e `x0` a `x2`. O retorno volta
/// em `rax` ou `x0`.
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
    /// `bifurcar()`: duplica o processo. Devolve 0 ao filho e o identificador
    /// do filho ao pai.
    pub const BIFURCAR: u64 = 4;
    /// `executar(ptr, tamanho)`: troca a imagem do processo pela que o nome
    /// indicar. Não retorna em caso de sucesso — retorna noutro programa.
    pub const EXECUTAR: u64 = 5;
    /// `abrir(ptr, tamanho)`: abre o arquivo do caminho e devolve o descritor.
    pub const ABRIR: u64 = 6;
    /// `ler(descritor, ptr, tamanho)`: traz bytes de onde o descritor apontar
    /// e avança a posição dele.
    pub const LER: u64 = 7;
    /// `fechar(descritor)`: devolve a vaga do descritor à tabela.
    pub const FECHAR: u64 = 8;
    /// `esperar(id, ponteiro)`: espera um filho terminar.
    ///
    /// `id` zero espera qualquer filho; diferente de zero, aquele filho. O
    /// ponteiro, quando não é nulo, aponta para **dois** `i64`: o código de
    /// saída e se ele vale. Devolve o identificador do filho colhido.
    ///
    /// É a única chamada deste kernel que **bloqueia**: o fio sai da lista
    /// do escalonador e volta quando um filho sai.
    pub const ESPERAR: u64 = 9;
    /// `mapear(endereco, tamanho)`: dá ao processo memória nova, zerada,
    /// gravável e não executável, em `[endereco, endereco + tamanho)`.
    ///
    /// Quem escolhe o endereço é o processo, dentro de
    /// [`MAPEAVEL`](super::MAPEAVEL), e a faixa inteira precisa estar livre.
    /// Devolve zero, ou um erro — e, no erro, nada foi mapeado.
    pub const MAPEAR: u64 = 10;
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
    pub const SEM_MEMORIA: i64 = -5;
    pub const SEM_VAGA_DE_FIO: i64 = -6;
    pub const PROGRAMA_DESCONHECIDO: i64 = -7;
    /// A tabela de descritores do processo está cheia.
    pub const SEM_DESCRITOR: i64 = -8;
    /// O caminho não existe, ou não dá para resolvê-lo.
    pub const NAO_ENCONTRADO: i64 = -9;
    /// O caminho existe e não é um arquivo.
    ///
    /// Distinto de [`NAO_ENCONTRADO`] de propósito: um programa que tente
    /// abrir um diretório merece saber que errou o tipo, e não que o caminho
    /// não existe — a segunda resposta o manda procurar o erro no lugar
    /// errado.
    pub const NAO_EH_ARQUIVO: i64 = -10;
    /// Não há filho por quem esperar.
    ///
    /// Distinto de "nenhum filho terminou ainda", que não é erro e nem chega
    /// ao usuário: aquele caso põe o fio para dormir. Este diz que esperar
    /// seria esperar para sempre.
    pub const SEM_FILHOS: i64 = -11;
    /// Parte da faixa pedida a `mapear` já está mapeada.
    ///
    /// Distinto de [`ENDERECO_INVALIDO`]: a faixa é legítima, e o processo é
    /// que já a usa. Mapear por cima trocaria em silêncio memória que ele
    /// ainda lê por páginas zeradas.
    pub const JA_MAPEADO: i64 = -12;
}

/// Os descritores que todo processo recebe abertos.
///
/// Os números são os do Unix, e isso é deliberado: não porque o Duke pretenda
/// ser POSIX, mas porque qualquer pessoa que já escreveu um programa sabe de
/// cor o que 1 e 2 significam. Inventar uma numeração própria cobraria esse
/// conhecimento de volta sem devolver nada.
pub mod padrao {
    /// Leitura. Reservado: ainda não há de onde ler, e **escrever nele é
    /// erro** — é o caso que prova que a tabela é consultada de verdade.
    pub const ENTRADA: u64 = 0;
    /// Saída comum. Vai para o log do kernel em nível `info`.
    pub const SAIDA: u64 = 1;
    /// Saída de erro. Vai para o mesmo log em nível `error`.
    pub const ERRO: u64 = 2;
}

/// Onde o espaço do usuário começa.
///
/// Uma faixa baixa e modesta, bem longe do heap do kernel (64 GiB), das
/// pilhas de fio (128 GiB) e do kernel. No x86 o kernel vive na metade alta,
/// então qualquer endereço aqui é inequivocamente do usuário; no ARM o kernel
/// está em `0x4008_0000`, e por isso a faixa começa acima dos 4 GiB — não há
/// como confundir uma com a outra.
pub const BASE: u64 = 0x0000_0001_0000_0000;
/// Fim exclusivo da faixa do usuário.
pub const TETO: u64 = BASE + 0x1000_0000;

/// Quantas páginas de pilha um processo recebe.
///
/// Dezesseis — 64 KiB. Os programas montados à mão viviam com uma, e um
/// programa compilado não vive: um `format!` com a pilha de depuração de uma
/// função genérica passa de 4 KiB sem ninguém perceber, e o que se perceberia
/// seria a página de guarda.
pub const PAGINAS_DA_PILHA: u64 = 16;

/// O tamanho de página que esta ABI assume nas duas arquiteturas.
pub const PAGINA: u64 = 4096;

/// A faixa onde `mapear` aceita criar memória: `[inicio, fim)`.
///
/// # O mapa, de baixo para cima
///
/// ```text
///   BASE                código e dados do programa (até 64 MiB)
///   BASE + 64 MiB       ┐
///        …              │ MAPEAVEL: o monte e o que mais o processo mapear
///   TETO - 16 MiB       ┘
///        …              não mapeado
///   TETO - 68 KiB       página de guarda
///   TETO - 64 KiB       pilha
///   TETO
/// ```
///
/// Os limites são largos dos dois lados de propósito: uma faixa que
/// encostasse no programa ou na pilha faria um `mapear` legítimo depender
/// do tamanho de um executável, ou de quanto a pilha cresceu.
pub const MAPEAVEL: (u64, u64) = (BASE + 0x0400_0000, TETO - 0x0100_0000);

// O mapa acima só vale se as fatias não se sobrepõem, e é o compilador quem
// confere.
const _: () = assert!(MAPEAVEL.0 < MAPEAVEL.1);
const _: () = assert!(MAPEAVEL.1 <= TETO - (PAGINAS_DA_PILHA + 1) * PAGINA);
const _: () = assert!(MAPEAVEL.0.is_multiple_of(PAGINA) && MAPEAVEL.1.is_multiple_of(PAGINA));
