//! A identidade do Duke no disco: a área do selo, e o que o boot decide
//! com ela.
//!
//! # A identidade
//!
//! A chave estática X25519 do canal dos agentes — a que eles fixam, e de
//! que o kernel deriva os segredos da persistência: a cifra do journal, a
//! senha da âncora, a do índice de geração, as do armazém. Numa máquina de
//! produção ela nasce no primeiro boot, sorteada pelo kernel, e fica
//! selada no TPM — ver [`crate::cofre`]. Não muda depois: o journal, os
//! índices de NV e o armazém dependem dela, e uma identidade nova por cima
//! deles seria uma máquina que não abre o próprio estado.
//!
//! # A área
//!
//! O selado não cabe no journal — o journal só abre com a chave que ele
//! guarda — e mora numa área própria: dois setores no começo da reserva do
//! fim da partição de estado, fora das regiões do journal e fora da limpeza
//! do cofre. Duas cópias iguais, escritas uma de cada vez, cada uma
//! descarregada antes da outra: uma queda no meio deixa uma inteira.
//!
//! ```text
//!   0  "DUKEIDT1"          a magia
//!   8  versão u16 LE       1
//!  10  tamanho u16 LE      do bloco privado, de 1 a 256
//!  12  reservado u32       zero
//!  16  ek [64]             o ponto da EK do TPM em que nasceu: x ‖ y
//!  80  pública [32]        a chave pública da identidade
//! 112  único [32]          o `unique` da parte pública do selado
//! 144  privado [256]       o bloco privado, completado com zeros
//! 400  zeros               até 480
//! 480  SHA-256 [32]        dos bytes 0 a 480
//! ```
//!
//! O resumo pega o setor estragado — uma escrita cortada, um bit que
//! mudou —, e não o mexido de propósito: quem escreve no disco refaz o
//! resumo. Contra esse a defesa é outra, e está no caminho de abrir: um
//! selado mexido não passa do `TPM2_Load`; uma EK trocada não passa da
//! conexão, que a confere antes de qualquer sessão; uma pública trocada
//! não confere com a chave aberta. O que sobra a quem escreve no disco é
//! recusar o boot — e isso ele já consegue apagando o journal.
//!
//! # A decisão
//!
//! [`decidir`] olha as duas cópias, se a partição tem journal e se o TPM
//! tem estado do Duke, e diz o que o boot faz — antes de qualquer
//! comando que mude alguma coisa:
//!
//! | cópias | journal | TPM | decisão |
//! |---|---|---|---|
//! | duas inteiras e diferentes | — | — | recusa |
//! | uma inteira, ou duas iguais | — | ausente | recusa |
//! | uma inteira, ou duas iguais | — | presente | abre; a outra, se não é igual, é reparada |
//! | nenhuma inteira, alguma ilegível | — | — | recusa |
//! | nenhuma inteira | há | — | recusa |
//! | nenhuma inteira | não há | ausente | recusa |
//! | nenhuma inteira | não há | com índice do Duke | recusa |
//! | nenhuma inteira | não há | sem índice do Duke | nasce |
//!
//! Nascer exige uma instalação nova: nenhum selo, nenhum journal, nenhum
//! índice. Qualquer outra coisa é estado que depende de uma identidade
//! anterior, e a recusa diz qual. Uma cópia estragada sem nada ao redor é
//! o nascimento que caiu no meio da escrita, e nascer de novo não perde
//! nada: nenhum estado chegou a depender da chave sorteada.
//!
//! Reinstalar é decidido fora daqui: o TPM limpo e a partição de estado
//! zerada — a regra do cofre. Não há cópia da identidade em lugar nenhum
//! além do selo: uma máquina que perde o selo, ou o TPM, perde a
//! identidade, e o que dependia dela.

use crate::cofre::{MAIOR_PRIVADO, SeladoDaIdentidade};
use crate::cripto::{self, TAM};

/// O tamanho de uma cópia da área: um setor.
pub const TAM_AREA: usize = 512;

/// O começo de toda cópia.
const MAGIA: [u8; 8] = *b"DUKEIDT1";
/// A versão do formato.
const VERSAO: u16 = 1;
/// Onde cada campo começa.
const EK: usize = 16;
const PUBLICA: usize = 80;
const UNICO: usize = 112;
const PRIVADO: usize = 144;
/// Onde o resumo começa: tudo antes dele é resumido.
const RESUMO: usize = TAM_AREA - TAM;

/// O que uma cópia guarda.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Area {
    /// O ponto da EK do TPM em que a identidade nasceu: `x ‖ y`. O boot
    /// conecta esperando esta EK — ver [`crate::Ancora::conectar`].
    pub ek: [u8; 2 * TAM],
    /// A chave pública da identidade. Depois de aberta, a privada tem de
    /// dar esta: a conferência que pega uma área trocada.
    pub publica: [u8; TAM],
    /// O selado da chave privada.
    pub selado: SeladoDaIdentidade,
}

impl Area {
    /// A cópia como vai para o disco.
    pub fn em_bytes(&self) -> [u8; TAM_AREA] {
        let mut b = [0u8; TAM_AREA];
        let privado = self.selado.privado();
        b[..8].copy_from_slice(&MAGIA);
        b[8..10].copy_from_slice(&VERSAO.to_le_bytes());
        b[10..12].copy_from_slice(&(privado.len() as u16).to_le_bytes());
        b[EK..PUBLICA].copy_from_slice(&self.ek);
        b[PUBLICA..UNICO].copy_from_slice(&self.publica);
        b[UNICO..PRIVADO].copy_from_slice(self.selado.unico());
        b[PRIVADO..PRIVADO + privado.len()].copy_from_slice(privado);
        let resumo = cripto::resumo(&[&b[..RESUMO]]);
        b[RESUMO..].copy_from_slice(&resumo);
        b
    }
}

/// O que uma cópia diz.
///
/// A válida leva a área inteira, e as outras nada: o pacote não tem
/// `alloc` para pô-la numa caixa, e uma leitura vive na pilha do boot por
/// um instante.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Leitura {
    /// Inteira: o formato e o resumo conferem.
    Valida(Area),
    /// O setor zerado: nada foi escrito ali.
    Vazia,
    /// Escrito, e estragado: a magia, a versão, um tamanho, um byte que
    /// devia ser zero, ou o resumo.
    Estragada,
    /// O disco não leu o setor.
    Ilegivel,
}

/// Lê uma cópia.
pub fn ler(b: &[u8; TAM_AREA]) -> Leitura {
    if b.iter().all(|&x| x == 0) {
        return Leitura::Vazia;
    }
    if b[..8] != MAGIA
        || u16::from_le_bytes([b[8], b[9]]) != VERSAO
        || b[12..16] != [0; 4]
        || !cripto::iguais(&cripto::resumo(&[&b[..RESUMO]]), &b[RESUMO..])
    {
        return Leitura::Estragada;
    }
    let tam = u16::from_le_bytes([b[10], b[11]]) as usize;
    if tam == 0 || tam > MAIOR_PRIVADO || b[PRIVADO + tam..RESUMO].iter().any(|&x| x != 0) {
        return Leitura::Estragada;
    }
    let Ok(selado) = SeladoDaIdentidade::de_partes(&b[UNICO..PRIVADO], &b[PRIVADO..PRIVADO + tam])
    else {
        return Leitura::Estragada;
    };
    let mut ek = [0u8; 2 * TAM];
    ek.copy_from_slice(&b[EK..PUBLICA]);
    let mut publica = [0u8; TAM];
    publica.copy_from_slice(&b[PUBLICA..UNICO]);
    Leitura::Valida(Area {
        ek,
        publica,
        selado,
    })
}

/// O que o boot faz com a identidade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decisao {
    /// Abrir o selado da cópia `copia`. Com `reparar`, a outra não é igual
    /// a ela, e é reescrita com ela depois de aberta.
    Abrir { copia: usize, reparar: bool },
    /// Uma instalação nova: sortear a chave, selar, gravar as duas cópias.
    Nascer,
    /// Nenhuma identidade neste boot.
    Recusar(Recusa),
}

/// Por que o boot fica sem identidade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// As duas cópias inteiras dizem coisas diferentes: nenhuma sequência
    /// de escritas do kernel faz isso.
    CopiasDivergem,
    /// Nenhuma cópia inteira, e uma o disco não leu: pode haver um selo
    /// ali.
    AreaIlegivel,
    /// Nenhuma cópia inteira, e a partição tem journal: um estado que
    /// depende de uma identidade cujo selo sumiu.
    SemSelo,
    /// Sem TPM: o selo não abre, e a identidade não tem onde nascer.
    SemTpm,
    /// Nenhuma cópia inteira, e o TPM tem índices do Duke: o estado de
    /// outra instalação, que só sai com o TPM limpo.
    TpmDeOutraInstalacao,
}

impl Recusa {
    /// Uma frase para o log, a auditoria e o `system.info` — que cabe
    /// inteira no detalhe de um registro da auditoria
    /// (`politica::auditoria::MAIOR_DETALHE`, 96 bytes).
    pub fn motivo(self) -> &'static str {
        match self {
            Recusa::CopiasDivergem => "as duas copias do selo da identidade divergem",
            Recusa::AreaIlegivel => "o disco nao leu a area do selo da identidade",
            Recusa::SemSelo => {
                "a particao de estado tem journal e nenhum selo: a identidade de que ele depende se perdeu"
            }
            Recusa::SemTpm => "sem TPM: a identidade selada nao abre, nem nasce",
            Recusa::TpmDeOutraInstalacao => {
                "o TPM guarda o estado de outra instalacao: reinstalar exige o TPM limpo"
            }
        }
    }
}

/// A decisão — ver o cabeçalho do módulo. `journal` diz se alguma região
/// da partição de estado começa por um registro do journal; `tpm`, `None`
/// sem TPM, e com ele se algum índice de NV do Duke existe.
pub fn decidir(copias: &[Leitura; 2], journal: bool, tpm: Option<bool>) -> Decisao {
    if let [Leitura::Valida(a), Leitura::Valida(b)] = copias
        && a != b
    {
        return Decisao::Recusar(Recusa::CopiasDivergem);
    }
    if let Some(copia) = copias.iter().position(|c| matches!(c, Leitura::Valida(_))) {
        if tpm.is_none() {
            return Decisao::Recusar(Recusa::SemTpm);
        }
        let reparar = !matches!(copias[1 - copia], Leitura::Valida(_));
        return Decisao::Abrir { copia, reparar };
    }
    if copias.contains(&Leitura::Ilegivel) {
        return Decisao::Recusar(Recusa::AreaIlegivel);
    }
    if journal {
        return Decisao::Recusar(Recusa::SemSelo);
    }
    match tpm {
        None => Decisao::Recusar(Recusa::SemTpm),
        Some(true) => Decisao::Recusar(Recusa::TpmDeOutraInstalacao),
        Some(false) => Decisao::Nascer,
    }
}
