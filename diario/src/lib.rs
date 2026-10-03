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
//! # A âncora
//!
//! Cada registro confirma um valor do contador do TPM: o primeiro, um a
//! mais do que o contador tinha quando o journal nasceu; cada outro, um a
//! mais que o anterior. O protocolo de uma gravação é: montar o registro
//! com a âncora seguinte, escrevê-lo, descarregar, e só então avançar o
//! contador. No boot, [`julgar`] compara o último registro com o contador
//! e diz se o disco é o atual, se a última gravação ficou a um passo de
//! terminar, ou se o disco é anterior ao que o TPM já viu.

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

/// Lê o journal inteiro de `meio`, abrindo cada registro com `chave`.
///
/// Só devolve erro quando o meio não lê. Um registro que não abre não é
/// erro daqui: é onde a leitura para, e o que isso significa depende da
/// âncora — ver [`julgar`].
pub fn ler<M: Meio>(meio: &mut M, chave: &[u8; 32]) -> Result<Lido, &'static str> {
    let total = meio.setores();
    let aead = XChaCha20Poly1305::new(&(*chave).into());
    let mut registros = Vec::new();
    let mut setor = 0u64;
    let mut elo = elo_inicial();
    let mut cabecalho = [0u8; TAM_SETOR];
    let parada = loop {
        if setor >= total {
            break Parada::Fim;
        }
        meio.ler(setor, &mut cabecalho)?;
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
        let esperada = registros.len() as u64;
        if sequencia != esperada {
            break ilegivel("sequencia fora de ordem");
        }
        if let Some(anterior) = registros.last().map(|r: &Registro| r.ancora)
            && Some(ancora) != anterior.checked_add(1)
        {
            break ilegivel("a ancora nao segue a do registro anterior");
        }

        let mut inteiro = alloc::vec![0u8; setores as usize * TAM_SETOR];
        inteiro[..TAM_SETOR].copy_from_slice(&cabecalho);
        if setores > 1 {
            meio.ler(setor + 1, &mut inteiro[TAM_SETOR..])?;
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
        let mut claro = inteiro[TAM_CABECALHO..fim_cifrado].to_vec();
        if aead
            .decrypt_inout_detached(
                &nonce.into(),
                &aad,
                claro.as_mut_slice().into(),
                &etiqueta.into(),
            )
            .is_err()
        {
            claro.zeroize();
            break ilegivel("o registro nao abre com esta chave, neste lugar");
        }
        let proximo_elo: [u8; 32] =
            Blake2s256::digest(&inteiro[..fim_cifrado + TAM_ETIQUETA]).into();
        let registro = Registro {
            sequencia,
            ancora,
            tipo: u16_em(&claro, 0),
            geracao: u64_em(&claro, 2),
            versao_da_politica: u64_em(&claro, 10),
            tempo: u64_em(&claro, 18),
            conteudo: claro[TAM_PREFIXO..].to_vec(),
        };
        claro.zeroize();
        registros.push(registro);
        elo = proximo_elo;
        setor += setores as u64;
    };
    Ok(Lido {
        registros,
        parada,
        proximo_setor: setor,
        elo,
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
    elo: [u8; 32],
    setores: u64,
}

/// O que é preciso para escrever o próximo registro.
pub struct Escritor {
    proximo_setor: u64,
    proxima_sequencia: u64,
    elo: [u8; 32],
    /// O valor do contador do TPM hoje — o que o último registro confirmou,
    /// ou o que o contador tinha quando o journal nasceu.
    ancora: u64,
    total: u64,
}

/// O conteúdo de um registro: o que ele diz, e o estado em que deixa o
/// sistema.
pub struct Conteudo<'a> {
    pub tipo: u16,
    pub geracao: u64,
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
        Escritor {
            proximo_setor: lido.proximo_setor,
            proxima_sequencia: lido.registros.len() as u64,
            elo: lido.elo,
            ancora,
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
        if conteudo.dados.len() > MAIOR_CONTEUDO {
            return Err("conteudo maior que um registro");
        }
        let ancora = self
            .ancora
            .checked_add(1)
            .ok_or("o contador da ancora esgotou")?;
        let tamanho = TAM_PREFIXO + conteudo.dados.len();
        let setores = setores_para(tamanho) as u64;
        if self.proximo_setor + setores > self.total {
            return Err("a particao de estado esta cheia");
        }
        let mut bytes = alloc::vec![0u8; setores as usize * TAM_SETOR];
        bytes[..8].copy_from_slice(&MAGIA);
        bytes[8..10].copy_from_slice(&VERSAO.to_le_bytes());
        bytes[12..16].copy_from_slice(&(setores as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.proxima_sequencia.to_le_bytes());
        bytes[24..32].copy_from_slice(&ancora.to_le_bytes());
        bytes[32..36].copy_from_slice(&(tamanho as u32).to_le_bytes());
        bytes[40..64].copy_from_slice(&nonce);

        let fim_cifrado = TAM_CABECALHO + tamanho;
        {
            let claro = &mut bytes[TAM_CABECALHO..fim_cifrado];
            claro[0..2].copy_from_slice(&conteudo.tipo.to_le_bytes());
            claro[2..10].copy_from_slice(&conteudo.geracao.to_le_bytes());
            claro[10..18].copy_from_slice(&conteudo.versao_da_politica.to_le_bytes());
            claro[18..26].copy_from_slice(&conteudo.tempo.to_le_bytes());
            claro[TAM_PREFIXO..].copy_from_slice(conteudo.dados);
        }
        let mut aad = [0u8; TAM_CABECALHO + 32];
        aad[..TAM_CABECALHO].copy_from_slice(&bytes[..TAM_CABECALHO]);
        aad[TAM_CABECALHO..].copy_from_slice(&self.elo);
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
        Ok(Montado {
            setor: self.proximo_setor,
            bytes,
            ancora,
            elo,
            setores,
        })
    }

    /// O registro montado foi escrito, descarregado, e o contador avançou
    /// para a âncora dele: o próximo vai depois.
    pub fn confirmar(&mut self, montado: &Montado) {
        self.proximo_setor = montado.setor + montado.setores;
        self.proxima_sequencia += 1;
        self.elo = montado.elo;
        self.ancora = montado.ancora;
    }

    /// O valor do contador que o journal confirmou por último.
    pub fn ancora(&self) -> u64 {
        self.ancora
    }

    /// Quantos setores ainda cabem.
    pub fn livres(&self) -> u64 {
        self.total - self.proximo_setor
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
    pub fn novo(piso: u64) -> Relogio {
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
