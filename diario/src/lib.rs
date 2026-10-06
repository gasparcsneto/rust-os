//! O journal da persistência do Duke.
//!
//! # O que é
//!
//! Uma sequência de registros na partição de estado, só de acréscimo. Cada
//! registro é cifrado e autenticado (XChaCha20-Poly1305), e a autenticação
//! de cada um cobre o resumo do anterior: um registro só se lê no lugar em
//! que foi escrito, depois exatamente daquele que o precedeu. Nada é
//! reescrito no lugar.
//!
//! # O formato
//!
//! Um registro ocupa um número inteiro de setores de 512 bytes:
//!
//! ```text
//! cabeçalho, em claro (64 bytes)
//!    0  "DUKEDIA1"          a magia
//!    8  versão     u16 LE   do formato
//!   10  reservado  u16      zero
//!   12  setores    u32 LE   quantos setores o registro ocupa, com este
//!   16  sequência  u64 LE   0, 1, 2… — o lugar do registro no journal
//!   24  âncora     u64 LE   o valor do contador do TPM que ele confirma
//!   32  tamanho    u32 LE   do texto cifrado, sem a etiqueta
//!   36  reservado  u32      zero
//!   40  nonce      24 bytes sorteado, um por registro
//! texto cifrado (`tamanho` bytes) e etiqueta (16 bytes)
//! zeros até o fim do último setor
//! ```
//!
//! O texto claro é `tipo u16 | geração u64 | versão da política u64 |
//! tempo u64 | conteúdo`. Os dados associados da cifra são o cabeçalho
//! inteiro **e** o elo — o resumo BLAKE2s do registro anterior (cabeçalho,
//! texto cifrado e etiqueta). O elo não está no disco: quem lê o recalcula,
//! e um registro fora do seu lugar não abre.
//!
//! O tipo, a geração e o tempo vão cifrados: dizer no disco que houve uma
//! revogação, e quando, já é dizer algo. O que fica em claro é só o que é
//! preciso para achar o próximo registro e conferir a âncora.
//!
//! # Por que o nonce é sorteado
//!
//! Porque o óbvio — a sequência, ou a âncora — se repete. Um disco
//! restaurado de uma cópia antiga volta a sequências já usadas, e o kernel,
//! até descobrir a restauração, escreveria nelas com a mesma chave. A
//! mesma chave com o mesmo nonce em dois textos diferentes entrega o
//! XOR dos dois a quem tiver os dois discos. Com 192 bits sorteados, a
//! repetição não acontece por acaso — e é para isso que o XChaCha tem o
//! nonce longo.
//!
//! # A geração
//!
//! Cada registro diz a geração administrativa em que deixa o sistema, e ela
//! não é escolhida por quem escreve: um registro de operação
//! ([`estado::tipo::OPERACAO`]) sobe um, qualquer outro repete a do
//! anterior. O escritor a calcula, e o leitor confere a regra em cada
//! registro depois do primeiro — a geração de um journal é, portanto, o
//! número de operações de autoridade que ele contém desde o seu começo, e
//! um salto ou uma volta param a leitura como qualquer outro defeito.
//!
//! # A âncora
//!
//! Cada registro confirma um valor do contador do TPM: o primeiro, um a
//! mais do que o contador tinha quando o journal nasceu; cada outro, um a
//! mais que o anterior. O protocolo de uma gravação é: montar o registro
//! com a âncora seguinte, escrevê-lo, descarregar, e só então avançar o
//! contador. No boot, [`julgar`] compara o último registro com o contador
//! e diz se o disco é o atual, se a última gravação ficou a um passo de
//! terminar, ou se o disco é anterior ao que o TPM já viu.
//!
//! # As duas regiões, e a compactação
//!
//! A partição tem duas regiões do mesmo tamanho ([`regioes`]), e o journal
//! mora numa delas. Quando ela enche, a compactação escreve na **outra** uma
//! base — o estado inteiro, em uma ou mais partes ([`estado::tipo::BASE`])
//! e um fecho ([`estado::tipo::BASE_FIM`]) — e só então avança o contador,
//! uma vez. As partes e o fecho têm todos a mesma âncora: a base é uma
//! gravação só, que o contador confirma inteira ou não confirma. A região
//! velha não é apagada nem tocada: até o contador avançar, ela é a atual;
//! depois, é um disco anterior ao que o TPM viu, e nunca mais é escolhida.
//!
//! No boot, as duas são lidas, e vale a de última âncora maior entre as
//! que são inteiras — uma que começa pela abertura, ou por uma base
//! fechada ([`escolher`]). Uma compactação interrompida deixa uma base sem
//! fecho, que não vale, e a região velha continua a atual; uma interrompida
//! depois da descarga e antes do contador deixa a base inteira com a
//! âncora seguinte, e o boot completa o avanço, como o de qualquer
//! registro.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroize;

pub mod estado;

/// O tamanho de um setor.
pub const TAM_SETOR: usize = 512;
/// O tamanho do cabeçalho em claro.
pub const TAM_CABECALHO: usize = 64;
/// O tamanho do nonce do XChaCha20.
pub const TAM_NONCE: usize = 24;
/// O tamanho da etiqueta do Poly1305.
const TAM_ETIQUETA: usize = 16;
/// O começo de todo registro.
const MAGIA: [u8; 8] = *b"DUKEDIA1";
/// A versão do formato.
const VERSAO: u16 = 1;
/// O texto claro antes do conteúdo: tipo, geração, versão da política e
/// tempo.
const TAM_PREFIXO: usize = 2 + 8 + 8 + 8;

/// O maior registro, em setores: 64 KiB. Cabe uma política inteira, com
/// folga, e não cabe nada que justificasse um registro sozinho maior.
pub const MAIOR_REGISTRO_EM_SETORES: u32 = 128;

/// O maior conteúdo que um registro leva.
pub const MAIOR_CONTEUDO: usize =
    MAIOR_REGISTRO_EM_SETORES as usize * TAM_SETOR - TAM_CABECALHO - TAM_ETIQUETA - TAM_PREFIXO;

/// Onde o journal mora: os setores da partição de estado, contados a
/// partir do começo dela.
///
/// O kernel implementa isto sobre o disco, restrito à janela de escrita; os
/// testes, sobre um vetor em memória que se corta e se estraga à vontade.
pub trait Meio {
    /// Quantos setores a partição tem.
    fn setores(&self) -> u64;
    /// Lê `destino.len()` bytes (múltiplo de setor) a partir de `setor`.
    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str>;
    /// Escreve `origem` (múltiplo de setor) a partir de `setor`. Escrito
    /// não é gravado: ver [`Meio::descarregar`].
    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str>;
    /// Põe no meio permanente tudo o que já foi escrito.
    fn descarregar(&mut self) -> Result<(), &'static str>;
}

/// Um registro lido e aberto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registro {
    pub sequencia: u64,
    pub ancora: u64,
    /// O nonce com que foi cifrado. Não é segredo — está em claro no
    /// cabeçalho —, e está aqui para quem precisa conferir que nenhum se
    /// repete.
    pub nonce: [u8; TAM_NONCE],
    pub tipo: u16,
    /// A geração administrativa depois deste registro.
    pub geracao: u64,
    /// A versão da política depois deste registro.
    pub versao_da_politica: u64,
    /// O tempo lógico em que ele foi escrito, em segundos desde 1970.
    pub tempo: u64,
    pub conteudo: Vec<u8>,
}

impl Drop for Registro {
    /// O conteúdo pode ser o corpo de uma mensagem: sai da memória com o
    /// registro.
    fn drop(&mut self) {
        self.conteudo.zeroize();
    }
}

/// Por que a leitura parou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parada {
    /// Um setor de cabeçalho todo em zeros: o journal acaba ali, limpo.
    Fim,
    /// Um registro que não se lê como deveria. Pode ser a cauda de uma
    /// gravação interrompida, ou um defeito — quem decide é [`julgar`],
    /// com a âncora.
    Ilegivel { setor: u64, motivo: &'static str },
    /// O registro no `setor` confirma uma âncora além do limite do percurso
    /// — ver [`percorrer_ate`]: ele existe, e não foi lido.
    Alem { setor: u64 },
}

/// O journal inteiro, como foi lido.
pub struct Lido {
    /// Os registros que abriram, em ordem.
    pub registros: Vec<Registro>,
    /// Por que parou.
    pub parada: Parada,
    /// O setor depois do último registro que abriu: onde o próximo vai.
    pub proximo_setor: u64,
    /// O resumo do último registro que abriu.
    pub elo: [u8; 32],
}

impl Lido {
    /// A âncora do último registro, ou `None` com o journal vazio.
    pub fn ultima_ancora(&self) -> Option<u64> {
        self.registros.last().map(|r| r.ancora)
    }

    /// O mesmo journal, sem os registros: o que [`percorrer`] devolve.
    pub fn percorrido(&self) -> Percorrido {
        Percorrido {
            quantos: self.registros.len() as u64,
            ultimo: self.registros.last().map(Ultimo::de),
            parada: self.parada,
            proximo_setor: self.proximo_setor,
            elo: self.elo,
            primeiro_tipo: self.registros.first().map(|r| r.tipo),
            base_fechada: self
                .registros
                .iter()
                .any(|r| r.tipo == estado::tipo::BASE_FIM),
        }
    }
}

/// O que se guarda do último registro lido: o que o próximo precisa para
/// se encadear, e o estado em que ele deixou o sistema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ultimo {
    pub ancora: u64,
    pub geracao: u64,
    pub versao_da_politica: u64,
    pub tempo: u64,
    pub tipo: u16,
}

impl Ultimo {
    fn de(r: &Registro) -> Ultimo {
        Ultimo {
            ancora: r.ancora,
            geracao: r.geracao,
            versao_da_politica: r.versao_da_politica,
            tempo: r.tempo,
            tipo: r.tipo,
        }
    }
}

/// O journal percorrido: quantos registros abriram, o último, e onde e por
/// que a leitura parou. Os registros mesmos foram entregues, um a um, a
/// quem percorreu — ver [`percorrer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Percorrido {
    pub quantos: u64,
    pub ultimo: Option<Ultimo>,
    pub parada: Parada,
    pub proximo_setor: u64,
    pub elo: [u8; 32],
    /// O tipo do primeiro registro: a abertura, ou uma parte da base.
    pub primeiro_tipo: Option<u16>,
    /// Se a base do começo da região foi fechada.
    pub base_fechada: bool,
}

impl Percorrido {
    /// Um journal vazio: o de uma região sem nada que valha. O próximo
    /// registro é o primeiro, encadeado ao elo inicial.
    pub fn vazio() -> Percorrido {
        Percorrido {
            quantos: 0,
            ultimo: None,
            parada: Parada::Fim,
            proximo_setor: 0,
            elo: elo_inicial(),
            primeiro_tipo: None,
            base_fechada: false,
        }
    }

    /// A âncora do último registro, ou `None` com o journal vazio.
    pub fn ultima_ancora(&self) -> Option<u64> {
        self.ultimo.map(|u| u.ancora)
    }

    /// Se a região é um journal inteiro: começa pela abertura, ou por uma
    /// base que se fechou. Uma base sem fecho é uma compactação que não
    /// terminou — nada dela vale.
    pub fn inteiro(&self) -> bool {
        match self.primeiro_tipo {
            Some(estado::tipo::ABERTURA) => true,
            Some(estado::tipo::BASE | estado::tipo::BASE_FIM) => self.base_fechada,
            _ => false,
        }
    }
}

/// Os setores da partição que o journal não usa, no fim: a bancada põe ali
/// o plano dela, e nenhuma região chega lá.
pub const RESERVA_NO_FIM: u64 = 64;

/// As duas regiões de uma partição de `setores` setores: o começo e o
/// tamanho de cada uma. Cada uma tem a metade do que sobra da reserva, ou
/// `limite` setores, se for menor — a suíte e a bancada encolhem as
/// regiões para encher uma depressa. A primeira começa no setor zero: um
/// journal de antes das regiões é o da primeira.
pub fn regioes(setores: u64, limite: Option<u64>) -> [(u64, u64); 2] {
    let metade = setores.saturating_sub(RESERVA_NO_FIM) / 2;
    let tamanho = limite.map_or(metade, |l| l.min(metade));
    [(0, tamanho), (metade, tamanho)]
}

/// Qual das duas regiões percorridas é o journal: a inteira de última
/// âncora maior. `None` se nenhuma é inteira — ou se as duas dizem a mesma
/// âncora, o que nenhuma sequência de gravações produz, e que não se
/// resolve escolhendo uma.
pub fn escolher(regioes: &[Percorrido; 2]) -> Option<usize> {
    let ancora = |i: usize| {
        regioes[i]
            .inteiro()
            .then(|| regioes[i].ultima_ancora())
            .flatten()
    };
    match (ancora(0), ancora(1)) {
        (Some(a), Some(b)) if a == b => None,
        (Some(a), Some(b)) => Some(if a > b { 0 } else { 1 }),
        (Some(_), None) => Some(0),
        (None, Some(_)) => Some(1),
        (None, None) => None,
    }
}

/// Por que um percurso não terminou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrompido<E> {
    /// O meio não leu.
    Meio(&'static str),
    /// Quem recebia os registros recusou o de número `sequencia`.
    Recusado { sequencia: u64, motivo: E },
}

/// A geração depois de um registro de `tipo`, sobre a geração `anterior`:
/// uma operação de autoridade sobe um; o resto não muda.
fn geracao_depois(anterior: u64, tipo: u16) -> Option<u64> {
    anterior.checked_add(u64::from(tipo == estado::tipo::OPERACAO))
}

/// A âncora que um registro de `tipo` tem de ter, depois do `anterior`: a
/// mesma, depois de uma parte da base — a base é uma gravação só — ou num
/// registro só de auditoria, que não avança o contador; a seguinte, em
/// todo outro. Ver [`estado::tipo::avanca_a_ancora`].
fn ancora_esperada(anterior: &Ultimo, tipo: u16) -> Option<u64> {
    if anterior.tipo == estado::tipo::BASE || !estado::tipo::avanca_a_ancora(tipo) {
        Some(anterior.ancora)
    } else {
        anterior.ancora.checked_add(1)
    }
}

/// O resumo com que o primeiro registro se encadeia.
fn elo_inicial() -> [u8; 32] {
    Blake2s256::digest(b"Duke diario: inicio v1").into()
}

fn u16_em(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32_em(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn u64_em(b: &[u8], i: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(v)
}

/// Quantos setores um registro com `tamanho` bytes de texto cifrado ocupa.
fn setores_para(tamanho: usize) -> u32 {
    (TAM_CABECALHO + tamanho + TAM_ETIQUETA).div_ceil(TAM_SETOR) as u32
}

/// Lê o journal inteiro de `meio`, abrindo cada registro com `chave`, e
/// devolve todos na memória. Para o journal de uma máquina de verdade —
/// até a partição inteira —, ver [`percorrer`], que guarda um de cada vez.
///
/// Só devolve erro quando o meio não lê. Um registro que não abre não é
/// erro daqui: é onde a leitura para, e o que isso significa depende da
/// âncora — ver [`julgar`].
pub fn ler<M: Meio>(meio: &mut M, chave: &[u8; 32]) -> Result<Lido, &'static str> {
    let mut registros = Vec::new();
    let p = percorrer(meio, chave, |r| {
        registros.push(r);
        Ok::<(), ()>(())
    })
    .map_err(|e| match e {
        Interrompido::Meio(m) => m,
        Interrompido::Recusado { .. } => "o percurso nao recusa nada aqui",
    })?;
    Ok(Lido {
        registros,
        parada: p.parada,
        proximo_setor: p.proximo_setor,
        elo: p.elo,
    })
}

/// Percorre o journal de `meio`, abrindo cada registro com `chave` e
/// entregando-o a `f`, na ordem. A memória que o percurso usa é a de um
/// registro, e não a do journal: o kernel tem pouco heap, e o journal pode
/// ocupar a partição inteira.
///
/// As conferências são as de [`ler`], e a leitura para no mesmo lugar. Um
/// `Err` de `f` interrompe o percurso ali, e volta com o número do
/// registro que ela recusou.
pub fn percorrer<M: Meio, E>(
    meio: &mut M,
    chave: &[u8; 32],
    f: impl FnMut(Registro) -> Result<(), E>,
) -> Result<Percorrido, Interrompido<E>> {
    percorrer_ate(meio, chave, u64::MAX, f)
}

/// Como [`percorrer`], parando antes do primeiro registro cuja âncora passa
/// de `ancora`: o que está depois é uma gravação que quem confirma as
/// âncoras ainda não confirmou.
///
/// # Para que serve
///
/// Para um journal cujo contador não é o TPM, e sim **outro journal**: o
/// do armazém, cujas âncoras o journal de estado confirma — ver o pacote
/// `armazem` e `docs/ARMAZENAMENTO.md`. Uma gravação do armazém escreve o
/// registro dele e só então o registro de estado que o confirma; uma queda
/// entre os dois deixa no armazém um registro além da âncora confirmada,
/// que não vale e é sobrescrito pelo seguinte. A parada é
/// [`Parada::Alem`], e o percurso devolvido é o de até ali — o escritor
/// continua dele.
pub fn percorrer_ate<M: Meio, E>(
    meio: &mut M,
    chave: &[u8; 32],
    ancora_maxima: u64,
    mut f: impl FnMut(Registro) -> Result<(), E>,
) -> Result<Percorrido, Interrompido<E>> {
    let total = meio.setores();
    let aead = XChaCha20Poly1305::new(&(*chave).into());
    let mut quantos = 0u64;
    let mut ultimo: Option<Ultimo> = None;
    let mut primeiro_tipo = None;
    let mut base_fechada = false;
    let mut setor = 0u64;
    let mut elo = elo_inicial();
    let mut cabecalho = [0u8; TAM_SETOR];
    let parada = loop {
        if setor >= total {
            break Parada::Fim;
        }
        meio.ler(setor, &mut cabecalho)
            .map_err(Interrompido::Meio)?;
        if cabecalho.iter().all(|&b| b == 0) {
            break Parada::Fim;
        }
        let ilegivel = |motivo| Parada::Ilegivel { setor, motivo };
        if cabecalho[..8] != MAGIA {
            break ilegivel("sem a magia do journal");
        }
        if u16_em(&cabecalho, 8) != VERSAO {
            break ilegivel("versao do formato desconhecida");
        }
        if u16_em(&cabecalho, 10) != 0 || u32_em(&cabecalho, 36) != 0 {
            break ilegivel("reservado diferente de zero");
        }
        let setores = u32_em(&cabecalho, 12);
        let tamanho = u32_em(&cabecalho, 32) as usize;
        if setores == 0
            || setores > MAIOR_REGISTRO_EM_SETORES
            || tamanho < TAM_PREFIXO
            || setores_para(tamanho) != setores
        {
            break ilegivel("tamanho de registro impossivel");
        }
        if setor + setores as u64 > total {
            break ilegivel("o registro passa do fim da particao");
        }
        let sequencia = u64_em(&cabecalho, 16);
        let ancora = u64_em(&cabecalho, 24);
        if sequencia != quantos {
            break ilegivel("sequencia fora de ordem");
        }
        // A âncora do cabeçalho é autenticada com o registro: uma forjada
        // não abriria. Além do limite, o registro não é aberto — nem
        // conferido: ele ainda não vale.
        if ancora > ancora_maxima {
            break Parada::Alem { setor };
        }

        let mut inteiro = alloc::vec![0u8; setores as usize * TAM_SETOR];
        inteiro[..TAM_SETOR].copy_from_slice(&cabecalho);
        if setores > 1 {
            meio.ler(setor + 1, &mut inteiro[TAM_SETOR..])
                .map_err(Interrompido::Meio)?;
        }
        let fim_cifrado = TAM_CABECALHO + tamanho;
        if inteiro[fim_cifrado + TAM_ETIQUETA..]
            .iter()
            .any(|&b| b != 0)
        {
            break ilegivel("bytes depois da etiqueta");
        }
        let mut aad = [0u8; TAM_CABECALHO + 32];
        aad[..TAM_CABECALHO].copy_from_slice(&inteiro[..TAM_CABECALHO]);
        aad[TAM_CABECALHO..].copy_from_slice(&elo);
        let nonce: [u8; TAM_NONCE] = inteiro[40..64].try_into().unwrap();
        let etiqueta: [u8; TAM_ETIQUETA] = inteiro[fim_cifrado..fim_cifrado + TAM_ETIQUETA]
            .try_into()
            .unwrap();
        // O elo é o resumo do registro como está no disco, cifrado: tirado
        // antes de decifrar no lugar — um registro de cada vez, sem cópia —,
        // e só vale se ele abrir.
        let proximo_elo: [u8; 32] =
            Blake2s256::digest(&inteiro[..fim_cifrado + TAM_ETIQUETA]).into();
        if aead
            .decrypt_inout_detached(
                &nonce.into(),
                &aad,
                inteiro[TAM_CABECALHO..fim_cifrado].as_mut().into(),
                &etiqueta.into(),
            )
            .is_err()
        {
            inteiro.zeroize();
            break ilegivel("o registro nao abre com esta chave, neste lugar");
        }
        let claro = &inteiro[TAM_CABECALHO..fim_cifrado];
        let registro = Registro {
            sequencia,
            ancora,
            nonce,
            tipo: u16_em(claro, 0),
            geracao: u64_em(claro, 2),
            versao_da_politica: u64_em(claro, 10),
            tempo: u64_em(claro, 18),
            conteudo: claro[TAM_PREFIXO..].to_vec(),
        };
        // O texto claro não fica no heap além do registro entregue.
        inteiro.zeroize();
        drop(inteiro);
        // A âncora depende do tipo deste registro, que só se sabe aberto: o
        // cabeçalho, com a âncora, é autenticado junto. Um registro só de
        // auditoria leva a mesma do anterior; todo outro, a seguinte.
        if let Some(anterior) = &ultimo
            && Some(registro.ancora) != ancora_esperada(anterior, registro.tipo)
        {
            break ilegivel("a ancora nao segue a do registro anterior");
        }
        if let Some(anterior) = ultimo
            && Some(registro.geracao) != geracao_depois(anterior.geracao, registro.tipo)
        {
            break ilegivel("geracao fora de sequencia");
        }
        // Um registro só de auditoria pode sumir num rollback para a última
        // âncora: um que carregue qualquer outra coisa não é entregue, e o
        // estado protegido nunca sai de um registro que não avançou o
        // contador.
        if registro.tipo == estado::tipo::AUDITORIA && !estado::so_de_auditoria(&registro.conteudo)
        {
            break ilegivel("registro so de auditoria com estado protegido");
        }
        // A base só no começo da região: a primeira parte é o primeiro
        // registro, e cada parte seguinte, e o fecho, vêm logo depois de
        // uma parte. Depois do fecho, nenhuma.
        let e_da_base = matches!(registro.tipo, estado::tipo::BASE | estado::tipo::BASE_FIM);
        let depois_de_parte = ultimo.is_some_and(|u| u.tipo == estado::tipo::BASE);
        if e_da_base && quantos > 0 && !depois_de_parte {
            break ilegivel("base fora do comeco da regiao");
        }
        if depois_de_parte && !e_da_base {
            break ilegivel("base sem fecho");
        }
        let tipo_lido = registro.tipo;
        let resumo = Ultimo::de(&registro);
        f(registro).map_err(|motivo| Interrompido::Recusado { sequencia, motivo })?;
        if quantos == 0 {
            primeiro_tipo = Some(tipo_lido);
        }
        base_fechada |= tipo_lido == estado::tipo::BASE_FIM;
        ultimo = Some(resumo);
        quantos += 1;
        elo = proximo_elo;
        setor += setores as u64;
    };
    Ok(Percorrido {
        quantos,
        ultimo,
        parada,
        proximo_setor: setor,
        elo,
        primeiro_tipo,
        base_fechada,
    })
}

/// Um registro pronto para ir ao disco.
pub struct Montado {
    /// Onde ele vai.
    pub setor: u64,
    /// Os bytes, setores inteiros.
    pub bytes: Vec<u8>,
    /// O valor do contador do TPM que ele confirma: o que o contador tem de
    /// valer depois de avançado.
    pub ancora: u64,
    /// A geração em que ele deixa o sistema: a do anterior, mais um se ele
    /// é uma operação de autoridade.
    pub geracao: u64,
    /// Se ele avança o contador — se é uma transição do estado protegido.
    /// Quem decide é o tipo: ver [`estado::tipo::avanca_a_ancora`].
    avanca: bool,
    elo: [u8; 32],
    setores: u64,
}

impl Montado {
    /// Se este registro avança o contador do TPM. Um que avança só se
    /// confirma com o contador ([`Escritor::confirmar`]); um que não avança,
    /// só sem ele ([`Escritor::confirmar_sem_contador`]).
    pub fn avanca(&self) -> bool {
        self.avanca
    }

    /// O resumo deste registro, como o seguinte se encadeia nele. Quem
    /// confirma um journal por fora — o journal de estado confirmando o do
    /// armazém — guarda a âncora **e** o elo: os dois juntos nomeiam
    /// exatamente este registro.
    pub fn elo(&self) -> [u8; 32] {
        self.elo
    }
}

/// O que é preciso para escrever o próximo registro.
pub struct Escritor {
    proximo_setor: u64,
    proxima_sequencia: u64,
    elo: [u8; 32],
    /// O valor do contador do TPM hoje — o que o último registro confirmou,
    /// ou o que o contador tinha quando o journal nasceu.
    ancora: u64,
    /// A geração do último registro, ou zero num journal vazio.
    geracao: u64,
    total: u64,
}

/// O conteúdo de um registro: o que ele diz, e o estado em que deixa o
/// sistema. A geração não está aqui: quem a dá é o tipo — ver
/// [`Montado::geracao`].
pub struct Conteudo<'a> {
    pub tipo: u16,
    pub versao_da_politica: u64,
    pub tempo: u64,
    pub dados: &'a [u8],
}

impl Escritor {
    /// Continua o journal `lido`, sobre o contador do TPM em `ancora`.
    ///
    /// Quem chama já julgou: `ancora` é o valor confirmado, e o próximo
    /// registro vai logo depois do último que abriu — por cima de qualquer
    /// cauda de uma gravação interrompida.
    pub fn continuar(lido: &Lido, ancora: u64, total: u64) -> Escritor {
        Escritor::depois_de(&lido.percorrido(), ancora, total)
    }

    /// O mesmo, a partir de um journal percorrido.
    pub fn depois_de(p: &Percorrido, ancora: u64, total: u64) -> Escritor {
        Escritor {
            proximo_setor: p.proximo_setor,
            proxima_sequencia: p.quantos,
            elo: p.elo,
            ancora,
            geracao: p.ultimo.map_or(0, |u| u.geracao),
            total,
        }
    }

    /// Monta o próximo registro, com o nonce sorteado por quem chama.
    pub fn montar(
        &self,
        chave: &[u8; 32],
        nonce: [u8; TAM_NONCE],
        conteudo: &Conteudo,
    ) -> Result<Montado, &'static str> {
        if matches!(conteudo.tipo, estado::tipo::BASE | estado::tipo::BASE_FIM) {
            return Err("a base se monta com Escritor::base");
        }
        if conteudo.tipo == estado::tipo::AUDITORIA && !estado::so_de_auditoria(conteudo.dados) {
            return Err("um registro so de auditoria nao leva estado protegido");
        }
        // Só um registro que avança o contador confirma a âncora seguinte;
        // um só de auditoria repete a de agora.
        let avanca = estado::tipo::avanca_a_ancora(conteudo.tipo);
        let ancora = self
            .ancora
            .checked_add(u64::from(avanca))
            .ok_or("o contador da ancora esgotou")?;
        let geracao = geracao_depois(self.geracao, conteudo.tipo).ok_or("a geracao esgotou")?;
        let (bytes, elo, setores) = selar(
            chave,
            nonce,
            &Posicao {
                setor: self.proximo_setor,
                sequencia: self.proxima_sequencia,
                ancora,
                elo: self.elo,
                total: self.total,
            },
            conteudo,
            geracao,
        )?;
        Ok(Montado {
            setor: self.proximo_setor,
            bytes,
            ancora,
            geracao,
            avanca,
            elo,
            setores,
        })
    }

    /// Começa a base de uma região nova, de `total` setores: a compactação.
    /// A base confirma a âncora seguinte à deste journal, na geração dele —
    /// a compactação não é uma operação de autoridade, e não sobe a
    /// geração.
    pub fn base(&self, total: u64) -> Result<Base, &'static str> {
        Ok(Base {
            posicao: Posicao {
                setor: 0,
                sequencia: 0,
                ancora: self
                    .ancora
                    .checked_add(1)
                    .ok_or("o contador da ancora esgotou")?,
                elo: elo_inicial(),
                total,
            },
            geracao: self.geracao,
        })
    }

    /// O registro montado foi escrito e descarregado, e o contador avançou:
    /// `contador` é o valor que o TPM devolveu, lido de volta. Só o valor
    /// que o registro confirma — a âncora dele — fecha a gravação, e o
    /// próximo vai depois.
    ///
    /// Outro valor é um contador que alguém mais avançou, ou um TPM que não
    /// é este: o disco e o TPM se separaram, e nada é confirmado — o
    /// escritor fica onde estava, e quem chama não grava mais nada até o
    /// próximo boot julgar.
    pub fn confirmar(&mut self, montado: &Montado, contador: u64) -> Result<(), &'static str> {
        if !montado.avanca {
            return Err("um registro so de auditoria nao se confirma com o contador");
        }
        if contador != montado.ancora {
            return Err("o contador do TPM nao foi para a ancora do registro");
        }
        self.avancar(montado);
        Ok(())
    }

    /// O registro montado, só de auditoria, foi escrito e descarregado: ele
    /// vale sem o contador, que não avança por ele. Um registro que avança
    /// o contador — uma transição do estado protegido — nunca se confirma
    /// assim: sem o contador, um disco devolvido a antes dele passaria.
    pub fn confirmar_sem_contador(&mut self, montado: &Montado) -> Result<(), &'static str> {
        if montado.avanca {
            return Err("um registro que avanca a ancora so se confirma com o contador");
        }
        self.avancar(montado);
        Ok(())
    }

    /// O escritor passa para depois de `montado`.
    fn avancar(&mut self, montado: &Montado) {
        self.proximo_setor = montado.setor + montado.setores;
        self.proxima_sequencia += 1;
        self.elo = montado.elo;
        self.ancora = montado.ancora;
        self.geracao = montado.geracao;
    }

    /// O valor do contador que o journal confirmou por último.
    pub fn ancora(&self) -> u64 {
        self.ancora
    }

    /// A geração do último registro.
    pub fn geracao(&self) -> u64 {
        self.geracao
    }

    /// Quantos setores a região tem, e quantos já estão ocupados.
    pub fn ocupacao(&self) -> (u64, u64) {
        (self.proximo_setor, self.total)
    }

    /// Quantos setores ainda cabem.
    pub fn livres(&self) -> u64 {
        self.total - self.proximo_setor
    }
}

/// Onde um registro vai, e o que o encadeia.
struct Posicao {
    setor: u64,
    sequencia: u64,
    ancora: u64,
    elo: [u8; 32],
    total: u64,
}

/// Monta um registro na posição `p`: os bytes, o elo dele e quantos setores
/// ocupa.
fn selar(
    chave: &[u8; 32],
    nonce: [u8; TAM_NONCE],
    p: &Posicao,
    conteudo: &Conteudo,
    geracao: u64,
) -> Result<(Vec<u8>, [u8; 32], u64), &'static str> {
    if conteudo.dados.len() > MAIOR_CONTEUDO {
        return Err("conteudo maior que um registro");
    }
    let tamanho = TAM_PREFIXO + conteudo.dados.len();
    let setores = setores_para(tamanho) as u64;
    if p.setor + setores > p.total {
        return Err("a particao de estado esta cheia");
    }
    let mut bytes = alloc::vec![0u8; setores as usize * TAM_SETOR];
    bytes[..8].copy_from_slice(&MAGIA);
    bytes[8..10].copy_from_slice(&VERSAO.to_le_bytes());
    bytes[12..16].copy_from_slice(&(setores as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&p.sequencia.to_le_bytes());
    bytes[24..32].copy_from_slice(&p.ancora.to_le_bytes());
    bytes[32..36].copy_from_slice(&(tamanho as u32).to_le_bytes());
    bytes[40..64].copy_from_slice(&nonce);

    let fim_cifrado = TAM_CABECALHO + tamanho;
    {
        let claro = &mut bytes[TAM_CABECALHO..fim_cifrado];
        claro[0..2].copy_from_slice(&conteudo.tipo.to_le_bytes());
        claro[2..10].copy_from_slice(&geracao.to_le_bytes());
        claro[10..18].copy_from_slice(&conteudo.versao_da_politica.to_le_bytes());
        claro[18..26].copy_from_slice(&conteudo.tempo.to_le_bytes());
        claro[TAM_PREFIXO..].copy_from_slice(conteudo.dados);
    }
    let mut aad = [0u8; TAM_CABECALHO + 32];
    aad[..TAM_CABECALHO].copy_from_slice(&bytes[..TAM_CABECALHO]);
    aad[TAM_CABECALHO..].copy_from_slice(&p.elo);
    let aead = XChaCha20Poly1305::new(&(*chave).into());
    let etiqueta = aead
        .encrypt_inout_detached(
            &nonce.into(),
            &aad,
            (&mut bytes[TAM_CABECALHO..fim_cifrado]).into(),
        )
        .map_err(|_| "a cifra recusou o registro")?;
    bytes[fim_cifrado..fim_cifrado + TAM_ETIQUETA].copy_from_slice(&etiqueta);
    let elo: [u8; 32] = Blake2s256::digest(&bytes[..fim_cifrado + TAM_ETIQUETA]).into();
    Ok((bytes, elo, setores))
}

/// A base de uma região nova, sendo montada: uma parte de cada vez, e o
/// fecho. Ver [`Escritor::base`].
///
/// Cada parte sai pronta para ser escrita no lugar dela; nenhuma é
/// confirmada sozinha. Só o fecho, depois de tudo escrito e descarregado e
/// do contador avançado, vira o escritor da região nova — ver
/// [`BaseFechada::confirmar`].
pub struct Base {
    posicao: Posicao,
    geracao: u64,
}

/// Um registro da base, pronto para o disco: onde vai e os bytes.
pub struct Parte {
    pub setor: u64,
    pub bytes: Vec<u8>,
}

/// A base fechada: o fecho, pronto para o disco, e o que ela confirma.
pub struct BaseFechada {
    pub setor: u64,
    pub bytes: Vec<u8>,
    /// O valor que o contador tem de ter depois de avançado.
    pub ancora: u64,
    escritor: Escritor,
}

impl Base {
    fn registro(
        &mut self,
        chave: &[u8; 32],
        nonce: [u8; TAM_NONCE],
        conteudo: &Conteudo,
    ) -> Result<Parte, &'static str> {
        let (bytes, elo, setores) = selar(chave, nonce, &self.posicao, conteudo, self.geracao)?;
        let setor = self.posicao.setor;
        self.posicao.setor += setores;
        self.posicao.sequencia += 1;
        self.posicao.elo = elo;
        Ok(Parte { setor, bytes })
    }

    /// Mais uma parte, com estas entradas.
    pub fn parte(
        &mut self,
        chave: &[u8; 32],
        nonce: [u8; TAM_NONCE],
        versao_da_politica: u64,
        tempo: u64,
        dados: &[u8],
    ) -> Result<Parte, &'static str> {
        self.registro(
            chave,
            nonce,
            &Conteudo {
                tipo: estado::tipo::BASE,
                versao_da_politica,
                tempo,
                dados,
            },
        )
    }

    /// O fecho, com os campos dele.
    pub fn fechar(
        mut self,
        chave: &[u8; 32],
        nonce: [u8; TAM_NONCE],
        versao_da_politica: u64,
        tempo: u64,
        dados: &[u8],
    ) -> Result<BaseFechada, &'static str> {
        let fecho = self.registro(
            chave,
            nonce,
            &Conteudo {
                tipo: estado::tipo::BASE_FIM,
                versao_da_politica,
                tempo,
                dados,
            },
        )?;
        let p = &self.posicao;
        Ok(BaseFechada {
            setor: fecho.setor,
            bytes: fecho.bytes,
            ancora: p.ancora,
            escritor: Escritor {
                proximo_setor: p.setor,
                proxima_sequencia: p.sequencia,
                elo: p.elo,
                ancora: p.ancora,
                geracao: self.geracao,
                total: p.total,
            },
        })
    }
}

impl BaseFechada {
    /// O resumo do fecho: o elo do último registro da base — ver
    /// [`Montado::elo`].
    pub fn elo(&self) -> [u8; 32] {
        self.escritor.elo
    }

    /// A base inteira foi escrita e descarregada, e o contador avançou para
    /// `contador`. Só a âncora da base fecha a compactação: o escritor da
    /// região nova continua depois do fecho. Outro valor é o disco e o TPM
    /// separados, e nada é confirmado.
    pub fn confirmar(self, contador: u64) -> Result<Escritor, &'static str> {
        if contador != self.ancora {
            return Err("o contador do TPM nao foi para a ancora da base");
        }
        Ok(self.escritor)
    }
}

/// O que fazer com o journal lido, dado o contador do TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Veredito {
    /// Sem journal e sem âncora: um sistema novo. Cria-se a âncora e o
    /// primeiro registro.
    Novo,
    /// O último registro confirma o valor do contador: o disco é o atual.
    Confere,
    /// O último registro confirma o valor **seguinte** ao do contador: ele
    /// foi escrito e descarregado, e a energia caiu antes de o contador
    /// avançar. O registro é válido — está inteiro, no lugar, autenticado —,
    /// e o que falta é avançar o contador uma vez.
    Completar,
    /// O disco não é o que o TPM diz que deveria ser.
    Recusado(Recusa),
}

/// Por que um journal é recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O journal termina antes do que o contador já confirmou: faltam
    /// registros. É um disco restaurado de uma cópia antiga, ou um registro
    /// confirmado que não abre mais — os dois, a mesma coisa para quem
    /// precisa saber se uma credencial foi revogada.
    DiscoAtrasado { disco: u64, ancora: u64 },
    /// O journal diz mais do que o contador viu, por mais de um passo: o
    /// TPM é outro, ou voltou.
    AncoraAtrasada { disco: u64, ancora: u64 },
    /// Há journal, e o TPM não tem a âncora: foi limpo, ou trocado.
    AncoraAusente,
    /// O TPM tem a âncora, e o journal está vazio: o disco foi apagado, ou
    /// trocado por um que nunca foi deste sistema.
    JournalApagado { ancora: u64 },
}

impl Recusa {
    /// Uma frase para o log e para a recusa das operações.
    pub fn motivo(&self) -> &'static str {
        match self {
            Recusa::DiscoAtrasado { .. } => {
                "o journal e anterior ao que a ancora do TPM ja confirmou: disco restaurado ou registro confirmado ilegivel"
            }
            Recusa::AncoraAtrasada { .. } => {
                "o journal passa da ancora do TPM em mais de um passo: o TPM nao e o deste disco"
            }
            Recusa::AncoraAusente => {
                "ha journal e o TPM nao tem a ancora: o TPM foi limpo ou trocado"
            }
            Recusa::JournalApagado { .. } => {
                "o TPM tem a ancora e o journal esta vazio: o disco foi apagado ou trocado"
            }
        }
    }
}

/// Julga o journal contra o contador do TPM.
///
/// `disco` é a âncora do último registro que abriu, ou `None` com o journal
/// vazio; `tpm` é o valor do contador, ou `None` se o TPM não tem a âncora.
///
/// A regra cobre de uma vez o que parece serem casos diferentes. Uma cauda
/// cortada por queda de energia é um registro que nunca foi confirmado: o
/// contador não chegou a ele, e o último que abriu é o que o contador diz
/// — [`Veredito::Confere`]. Um registro confirmado que alguém estragou é um
/// que o contador viu e que não abre — [`Recusa::DiscoAtrasado`]. Um disco
/// devolvido a uma cópia antiga também. Não é preciso adivinhar qual dos
/// três aconteceu: o contador sabe quantos registros têm de existir.
pub fn julgar(disco: Option<u64>, tpm: Option<u64>) -> Veredito {
    match (disco, tpm) {
        (None, None) => Veredito::Novo,
        (None, Some(ancora)) => Veredito::Recusado(Recusa::JournalApagado { ancora }),
        (Some(_), None) => Veredito::Recusado(Recusa::AncoraAusente),
        (Some(d), Some(t)) if d == t => Veredito::Confere,
        (Some(d), Some(t)) if Some(d) == t.checked_add(1) => Veredito::Completar,
        (Some(d), Some(t)) if d < t => Veredito::Recusado(Recusa::DiscoAtrasado {
            disco: d,
            ancora: t,
        }),
        (Some(d), Some(t)) => Veredito::Recusado(Recusa::AncoraAtrasada {
            disco: d,
            ancora: t,
        }),
    }
}

/// O tempo lógico: o RTC, com um piso que nunca desce.
///
/// O piso começa no tempo do último registro do journal e sobe a cada
/// leitura. Um RTC que volta — acertado à mão, sem bateria, uma máquina
/// virtual que sobe com a data que se manda — não faz o tempo lógico
/// voltar: ele fica parado no piso até o RTC passar dele de novo.
pub struct Relogio {
    piso: u64,
}

impl Relogio {
    /// Um relógio que nunca volta abaixo de `piso`.
    pub const fn novo(piso: u64) -> Relogio {
        Relogio { piso }
    }

    /// O tempo lógico agora, dado o que o RTC diz. Sem RTC, é o piso.
    pub fn agora(&mut self, rtc: Option<u64>) -> u64 {
        if let Some(r) = rtc
            && r > self.piso
        {
            self.piso = r;
        }
        self.piso
    }

    /// O piso, sem consultar o RTC.
    pub fn piso(&self) -> u64 {
        self.piso
    }
}

#[cfg(test)]
mod testes;
