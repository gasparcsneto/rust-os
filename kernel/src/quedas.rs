//! Quedas de energia em pontos exatos, só na compilação da bancada.
//!
//! # Para que serve
//!
//! A bancada de persistência corta a energia com `SIGKILL`, e um corte no
//! instante certo — entre a descarga do disco e o avanço do contador do
//! TPM, digamos — é questão de sorte: a janela tem milissegundos. Esta
//! compilação põe a sorte de lado. Ela lê um plano no último setor da
//! partição de estado — em que ponto, e em que gravação desde o boot —, e
//! quando chega lá avisa pelo canal do agente e congela a máquina. A
//! bancada vê o aviso e corta a energia: o disco e o TPM ficam exatamente
//! como estavam naquele ponto.
//!
//! # Por que só ali
//!
//! O módulo só existe com a feature `quedas`, que só a bancada pede — o
//! `cargo xtask invariantes` confere. Num kernel de produção não há plano a
//! ler, nem ponto em que congelar.
//!
//! # O plano
//!
//! ```text
//!   0  "DUKEQUED"   a magia
//!   8  ponto  u8    ver [`Ponto`]
//!   9  reservado
//!  12  gravação u32 LE   a n-ésima gravação desde o boot (1 é a primeira),
//!                        para os pontos de dentro de uma gravação
//!  16  tipo u16 LE       se não zero, só contam as gravações de registros
//!                        desse tipo
//!  18  limite u64 LE     se não zero, o tamanho de cada região do journal,
//!                        em setores — para encher uma depressa
//!  26  bandeiras u8      bit 0: o coletor não compacta; bit 1: o boot
//!                        não compacta; bit 2: a criação do journal
//!                        espera, cedendo, antes de gravar a abertura;
//!                        bit 3: o contador anda uma vez "de fora" no
//!                        boot, antes de ser lido; bit 4: as chaves no
//!                        formato de antes do cofre — ver
//!                        [`chaves_antigas`]; bit 5: no ponto
//!                        [`Ponto::AntesDaConfirmacao`], o pânico em vez de
//!                        congelar
//! ```
//!
//! O limite e as bandeiras servem à compactação: a bancada enche uma
//! região pequena, e escolhe onde a compactação acontece — no boot, para a
//! queda nela ser certa, ou em lugar nenhum, para ver o que o boot
//! seguinte encontra.
//!
//! O tipo existe por causa da auditoria: o coletor grava registros só de
//! auditoria quando quer, e a n-ésima gravação de qualquer tipo deixaria
//! de ser a mesma de uma corrida para outra. A n-ésima operação continua.

use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};

/// A magia do setor do plano.
const MAGIA: [u8; 8] = *b"DUKEQUED";

/// Onde a energia pode cair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ponto {
    /// O contador da âncora definido no TPM, e nunca avançado.
    AncoraDefinida = 1,
    /// O contador avançado uma vez, e o nascimento ainda não guardado.
    AncoraAvancada = 2,
    /// O nascimento guardado, e a abertura ainda não gravada.
    NascimentoGuardado = 3,
    /// Uma gravação montada, e nada escrito.
    AntesDaEscrita = 10,
    /// O registro escrito, e não descarregado.
    DepoisDaEscrita = 11,
    /// O registro descarregado, e o contador ainda não avançado.
    DepoisDaDescarga = 12,
    /// O contador avançado, e a gravação ainda não confirmada — nem a
    /// operação respondida.
    DepoisDoContador = 13,
    /// Na compactação: a primeira parte da base escrita, e nada mais.
    DepoisDaPrimeiraParte = 14,
    /// O incremento do contador respondido, e a leitura de volta ainda não
    /// feita.
    DepoisDoIncremento = 15,
    /// No boot: a EK conferida com a fixada, e o contador ainda não lido.
    DepoisDaChave = 16,
    /// Um lote do armazém inteiro no volume — os blocos e o registro do
    /// journal dele, descarregados —, e a confirmação ainda não começada no
    /// journal de estado. Conta como da gravação de estado que viria a
    /// seguir: a n-ésima do tipo do plano.
    LoteNoVolume = 17,
    /// Uma morte de chave: o registro da operação — a lápide, os selados
    /// das vivas para a geração seguinte, a geração pendente — confirmado
    /// pela âncora, e o índice de geração ainda não avançado. Conta como da
    /// gravação da operação.
    GeracaoPendente = 18,
    /// O índice de geração avançado, e a confirmação ainda não gravada.
    /// Conta como da gravação da operação.
    GeracaoAvancada = 19,
    /// No boot: as chaves do formato de antes do cofre seladas no TPM, e o
    /// registro da migração ainda não gravado.
    AntigasSeladas = 20,
    /// No boot: a compactação da limpeza feita, e nada zerado ainda.
    LimpezaComecou = 21,
    /// No boot: o primeiro pedaço de fora do journal zerado, e o resto não.
    LimpezaNoMeio = 22,
    /// No boot: a partição zerada fora do journal, e o registro do fim da
    /// limpeza ainda não gravado.
    LimpezaTerminada = 23,
    /// A atualização A/B: o controle de boot gravado pela n-ésima vez desde
    /// o boot — a gravação do plano —, uma cópia descarregada, e nada
    /// depois.
    ControleGravado = 24,
    /// A atualização A/B: no boot de uma tentativa, a versão nova
    /// conferida, e a confirmação ainda não gravada. Com a bandeira 5, em
    /// vez de congelar a máquina entra em pânico — a versão nova que cai de
    /// verdade, e reinicia sozinha.
    AntesDaConfirmacao = 25,
    /// A atualização A/B: o n-ésimo pedaço da versão nova escrito no slot
    /// inativo e descarregado — a gravação do plano —, e nada depois.
    NoMeioDaEncenacao = 26,
    /// O nascimento da identidade: a chave selada no TPM e conferida, e
    /// nenhuma cópia da área escrita.
    IdentidadeSelada = 27,
    /// O nascimento da identidade: a primeira cópia da área escrita e
    /// descarregada, e a segunda não.
    PrimeiraCopia = 28,
    /// O nascimento da identidade: as duas cópias escritas, e a chave
    /// ainda não em uso — a persistência nem começou.
    IdentidadeGravada = 29,
    /// A troca da própria senha: as três senhas digitadas, e nada
    /// conferido ainda — nem a sessão, nem a atual, nem a nova.
    TrocaDigitada = 30,
    /// A troca da própria senha: a atual conferida, a nova aceita e a
    /// credencial nova calculada, e a decisão ainda não refeita com a
    /// ordem das gravações na mão.
    SenhaConferida = 31,
    /// A troca da própria senha: a decisão feita, a credencial nova em
    /// memória e a decisão na cadeia da auditoria — e nada no journal.
    TrocaAutorizada = 32,
    /// A troca da própria senha: o registro dela confirmado pela âncora, e
    /// a resposta à pessoa ainda não dada.
    TrocaGravada = 33,
    /// A cópia de segurança: o setor em claro e a primeira parte dela no
    /// rascunho, e o resto não.
    CopiaNoMeio = 34,
    /// A restauração: a cópia lida e conferida inteira, o conteúdo dela em
    /// blocos livres do volume — que nenhum metadado aponta —, e nada
    /// preparado.
    RestauracaoConferida = 35,
    /// A restauração: a primeira parte da base com o armazém restaurado
    /// escrita na outra região do journal dos metadados, e nada mais.
    RestauracaoNaPrimeiraParte = 36,
    /// A restauração: a base inteira escrita e descarregada, e a
    /// confirmação ainda não começada no journal de estado.
    RestauracaoNaBase = 37,
    /// A restauração: confirmada pela âncora e em vigor em memória, e a
    /// resposta ainda não dada.
    RestauracaoGravada = 38,
}

static PONTO: AtomicU8 = AtomicU8::new(0);
static GRAVACAO: AtomicU32 = AtomicU32::new(0);
static TIPO: AtomicU16 = AtomicU16::new(0);
static LIMITE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BANDEIRAS: AtomicU8 = AtomicU8::new(0);
static GRAVACOES: AtomicU32 = AtomicU32::new(0);
/// Quantas vezes o controle de boot foi gravado desde o boot.
static CONTROLES: AtomicU32 = AtomicU32::new(0);
/// Quantos pedaços da versão nova foram escritos desde o boot.
static PEDACOS: AtomicU32 = AtomicU32::new(0);

/// Lê o plano do último setor da partição de estado, se houver um.
pub fn carregar<M: diario::Meio>(meio: &mut M) {
    let total = meio.setores();
    if total == 0 {
        return;
    }
    let mut setor = [0u8; 512];
    if meio.ler(total - 1, &mut setor).is_err() || setor[..8] != MAGIA {
        return;
    }
    let gravacao = u32::from_le_bytes([setor[12], setor[13], setor[14], setor[15]]);
    let tipo = u16::from_le_bytes([setor[16], setor[17]]);
    let mut limite = [0u8; 8];
    limite.copy_from_slice(&setor[18..26]);
    LIMITE.store(u64::from_le_bytes(limite), Ordering::Relaxed);
    BANDEIRAS.store(setor[26], Ordering::Relaxed);
    PONTO.store(setor[8], Ordering::Relaxed);
    GRAVACAO.store(gravacao, Ordering::Relaxed);
    TIPO.store(tipo, Ordering::Relaxed);
    crate::log_warn!(
        "quedas",
        "plano da bancada: a energia cai no ponto {} da gravacao {} (tipo {})",
        setor[8],
        gravacao,
        tipo
    );
}

/// O tamanho das regiões que o plano pede, se pede um.
pub fn limite() -> Option<u64> {
    match LIMITE.load(Ordering::Relaxed) {
        0 => None,
        l => Some(l),
    }
}

/// Se o plano tira a compactação do coletor.
pub fn coletor_nao_compacta() -> bool {
    BANDEIRAS.load(Ordering::Relaxed) & 1 != 0
}

/// Se o plano tira a compactação do boot.
pub fn boot_nao_compacta() -> bool {
    BANDEIRAS.load(Ordering::Relaxed) & 2 != 0
}

/// Se o plano faz o contador andar uma vez "de fora" no boot, antes de
/// ser lido: o que alguém com a senha do contador faria entre dois boots.
pub fn contador_de_fora() -> bool {
    BANDEIRAS.load(Ordering::Relaxed) & 8 != 0
}

/// Se o plano põe o kernel no formato de antes do cofre: a criação grava a
/// semente no journal, o boot não abre o cofre e não migra, e uma morte de
/// chave não avança a geração. É o kernel de antes, para a bancada da
/// migração ter um journal antigo de verdade — e só aqui.
pub fn chaves_antigas() -> bool {
    BANDEIRAS.load(Ordering::Relaxed) & 16 != 0
}

/// Se o plano faz a criação do journal esperar antes da abertura, com a
/// persistência já disponível: tempo para o coletor passar — e ele não
/// pode gravar nada antes da abertura.
pub fn esperar_na_abertura() -> bool {
    BANDEIRAS.load(Ordering::Relaxed) & 4 != 0
}

/// Uma gravação de um registro do `tipo` começou: conta, para os pontos
/// de dentro dela. Com um tipo no plano, só as desse tipo contam; as
/// outras não caem.
pub fn gravacao_comecou(tipo: u16) {
    let do_plano = TIPO.load(Ordering::Relaxed);
    if do_plano == 0 || do_plano == tipo {
        GRAVACOES.fetch_add(1, Ordering::Relaxed);
        DA_CONTA.store(true, Ordering::Relaxed);
    } else {
        DA_CONTA.store(false, Ordering::Relaxed);
    }
}

/// Se a gravação em curso é uma das que o plano conta.
static DA_CONTA: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Se o plano manda a energia cair aqui, ela cai: o aviso sai pelo canal
/// do agente, e a máquina congela com as interrupções desligadas. Nada
/// mais roda — nenhum outro fio, nenhuma escrita, nenhuma resposta.
pub fn aqui(p: Ponto) {
    if PONTO.load(Ordering::Relaxed) != p as u8 {
        return;
    }
    // Os pontos de dentro de uma gravação contam gravações; os do boot e
    // os da criação, não.
    let de_gravacao = !matches!(
        p,
        Ponto::AncoraDefinida
            | Ponto::AncoraAvancada
            | Ponto::NascimentoGuardado
            | Ponto::DepoisDaChave
            | Ponto::AntigasSeladas
            | Ponto::LimpezaComecou
            | Ponto::LimpezaNoMeio
            | Ponto::LimpezaTerminada
            | Ponto::IdentidadeSelada
            | Ponto::PrimeiraCopia
            | Ponto::IdentidadeGravada
            | Ponto::TrocaDigitada
            | Ponto::SenhaConferida
            | Ponto::TrocaAutorizada
            | Ponto::TrocaGravada
            | Ponto::CopiaNoMeio
            | Ponto::RestauracaoConferida
            | Ponto::RestauracaoNaPrimeiraParte
            | Ponto::RestauracaoNaBase
            | Ponto::RestauracaoGravada
    );
    if p == Ponto::LoteNoVolume {
        // A gravação de estado que confirmaria o lote ainda não começou: a
        // conta é a dela, a próxima.
        let tipo = TIPO.load(Ordering::Relaxed);
        if (tipo != 0 && tipo != diario::estado::tipo::ARMAZEM)
            || GRAVACOES.load(Ordering::Relaxed) + 1 != GRAVACAO.load(Ordering::Relaxed)
        {
            return;
        }
    } else if de_gravacao
        && (!DA_CONTA.load(Ordering::Relaxed)
            || GRAVACOES.load(Ordering::Relaxed) != GRAVACAO.load(Ordering::Relaxed))
    {
        return;
    }
    cair(p)
}

/// A n-ésima gravação de uma conta própria — a do controle, a dos pedaços
/// da versão nova —: cai no ponto `p` se o plano é ele e a conta chegou à
/// gravação do plano.
fn contar_e_cair(p: Ponto, conta: &AtomicU32) {
    let n = conta.fetch_add(1, Ordering::Relaxed) + 1;
    if PONTO.load(Ordering::Relaxed) == p as u8 && n == GRAVACAO.load(Ordering::Relaxed) {
        cair(p)
    }
}

/// O controle de boot acabou de ser gravado: o ponto
/// [`Ponto::ControleGravado`].
pub fn controle_gravado() {
    contar_e_cair(Ponto::ControleGravado, &CONTROLES);
}

/// Um pedaço da versão nova acabou de ser escrito: o ponto
/// [`Ponto::NoMeioDaEncenacao`].
pub fn encenacao_gravada() {
    contar_e_cair(Ponto::NoMeioDaEncenacao, &PEDACOS);
}

/// A versão nova vai se confirmar: o ponto [`Ponto::AntesDaConfirmacao`] —
/// congelar, ou, com a bandeira 5, o pânico.
pub fn antes_da_confirmacao() {
    if PONTO.load(Ordering::Relaxed) != Ponto::AntesDaConfirmacao as u8 {
        return;
    }
    if BANDEIRAS.load(Ordering::Relaxed) & 32 != 0 {
        panic!("queda: a versao nova cai antes de se confirmar");
    }
    cair(Ponto::AntesDaConfirmacao)
}

/// A energia cai aqui: o aviso sai pelo canal do agente, e a máquina
/// congela com as interrupções desligadas.
fn cair(p: Ponto) -> ! {
    crate::arch::sem_interrupcoes(|| {
        // A trava da serial pode estar na mão deste mesmo processador — no
        // modo post-mortem a resposta se escreve enquanto o handler
        // executa —, e ele não volta daqui: soltá-la à força não corre o
        // risco de ninguém. O `\n` do começo separa o aviso de uma resposta
        // escrita pela metade.
        //
        // SAFETY: a máquina congela logo abaixo, com as interrupções
        // desligadas e num processador só; nenhum dono da trava volta a
        // usá-la.
        unsafe { crate::serial::AGENT_LINK.force_unlock() };
        if let Some(mut guarda) = crate::serial::AGENT_LINK.try_lock()
            && let Some(porta) = guarda.as_mut()
        {
            let mut aviso = *b"\n{\"queda\":000}\n";
            let n = p as u8;
            aviso[10] = b'0' + n / 100;
            aviso[11] = b'0' + n / 10 % 10;
            aviso[12] = b'0' + n % 10;
            porta.write_bytes(&aviso);
        }
        loop {
            crate::arch::esperar_interrupcao();
        }
    });
    // O laço de cima não volta; este existe para o tipo.
    loop {
        crate::arch::esperar_interrupcao();
    }
}
