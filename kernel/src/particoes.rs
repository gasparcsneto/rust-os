//! A tabela de partições do disco.
//!
//! # Por que GPT e não MBR
//!
//! Porque é o que o disco tem. O MBR que mora no setor zero é de proteção:
//! ele existe para que uma ferramenta que não entenda GPT veja o disco como
//! ocupado em vez de vazio, e o que ele descreve é uma única partição falsa
//! cobrindo tudo. Ler aquilo como se fosse a verdade daria uma partição só,
//! do tamanho do disco, e nenhum sistema de arquivos dentro dela.
//!
//! # O que este módulo lê, e o que ele ignora
//!
//! Lê o cabeçalho e as entradas, e delas guarda o começo, o tamanho e o tipo.
//! Ignora as somas de verificação da própria GPT e a cópia de segurança no
//! fim do disco. As duas existem para detectar corrupção de uma tabela
//! escrita por outrem, e a resposta a uma tabela corrompida seria a mesma que
//! a resposta a uma tabela ausente — um kernel que não monta nada. Entram no
//! dia em que houver o que fazer de diferente.
//!
//! O que ele **não** ignora são os três campos do cabeçalho que viram conta de
//! endereço: onde começa o vetor de entradas, quantas são e quanto cada uma
//! ocupa. Ignorar uma soma de verificação custa não detectar uma corrupção;
//! ignorar esses três custa o kernel — ver [`planejar`], que é onde os três
//! são conferidos antes de qualquer aritmética.

/// Onde fica o cabeçalho da GPT.
const CABECALHO_EM: u64 = 1;

/// O que os primeiros oito bytes do cabeçalho trazem.
const ASSINATURA: &[u8; 8] = b"EFI PART";

/// Deslocamentos dentro do cabeçalho.
mod cabecalho {
    /// Onde começa o vetor de entradas, em LBA.
    pub const ENTRADAS_EM: usize = 72;
    /// Quantas entradas o vetor tem.
    pub const QUANTAS: usize = 80;
    /// Quantos bytes cada entrada ocupa.
    pub const TAMANHO: usize = 84;
}

/// Deslocamentos dentro de uma entrada.
mod entrada {
    /// O GUID que diz para que serve a partição.
    pub const TIPO: usize = 0;
    /// O primeiro e o último setor, inclusive.
    pub const PRIMEIRO: usize = 32;
    pub const ULTIMO: usize = 40;
}

/// Quantas partições este kernel guarda.
///
/// Oito. O disco tem duas, e o número existe para que uma tabela absurda vire
/// um teto em vez de um `Vec` crescendo com o que o disco disser.
pub const MAX: usize = 8;

/// Quantas entradas uma GPT pode declarar e ainda ser levada a sério.
///
/// A especificação não dá teto: o campo é um `u32`, e um cabeçalho pode dizer
/// quatro bilhões. Um disco de verdade diz 128 — é o que as ferramentas de
/// particionamento escrevem e o que o disco desta máquina traz.
///
/// O teto não é zelo. A varredura faz uma leitura de setor por entrada
/// declarada, e quatro bilhões delas a cem microssegundos cada são cinco dias
/// de boot. Um número absurdo aqui não corrompe nada — ele faz o kernel nunca
/// terminar de subir, que é a falha mais difícil de diagnosticar das três.
const MAX_ENTRADAS: u32 = 1024;

/// O GUID de uma partição de sistema EFI.
///
/// Os GUIDs da GPT são escritos num formato misto: os três primeiros campos
/// em little-endian e os dois últimos em big-endian. É por isso que
/// `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` começa com `28 73 2A C1` no disco —
/// e é o tipo de detalhe que, escrito errado, produz uma partição que existe
/// e nunca é reconhecida.
const GUID_ESP: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

/// O GUID de uma partição de dados do Linux, que é o que o `sgdisk` põe no
/// tipo `8300` e o que a raiz deste disco usa.
const GUID_DADOS: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// Para que serve uma partição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    /// Partição de sistema EFI: é dela que um firmware carrega o que boota.
    Esp,
    /// Dados: é onde a raiz mora.
    Dados,
    /// Qualquer outro GUID.
    Outro,
}

impl Tipo {
    pub fn como_str(self) -> &'static str {
        match self {
            Tipo::Esp => "esp",
            Tipo::Dados => "dados",
            Tipo::Outro => "outro",
        }
    }

    fn do_guid(guid: &[u8]) -> Tipo {
        if guid == GUID_ESP {
            Tipo::Esp
        } else if guid == GUID_DADOS {
            Tipo::Dados
        } else {
            Tipo::Outro
        }
    }
}

/// Uma partição, como a tabela a descreve.
#[derive(Clone, Copy, Debug)]
pub struct Particao {
    /// O primeiro setor, contado a partir do começo do disco.
    pub primeiro: u64,
    /// Quantos setores ela tem.
    pub setores: u64,
    pub tipo: Tipo,
}

/// As partições encontradas, e quantas são.
pub struct Tabela {
    particoes: [Option<Particao>; MAX],
}

impl Tabela {
    pub fn vazia() -> Tabela {
        Tabela {
            particoes: [None; MAX],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Particao> {
        self.particoes.iter().flatten()
    }

    /// A primeira partição de um tipo, se houver.
    pub fn primeira(&self, tipo: Tipo) -> Option<&Particao> {
        self.iter().find(|p| p.tipo == tipo)
    }
}

/// Lê um inteiro de 64 bits little-endian de dentro de um buffer.
fn u64_em(bytes: &[u8], deslocamento: usize) -> Option<u64> {
    let fatia = bytes.get(deslocamento..deslocamento + 8)?;
    Some(u64::from_le_bytes(fatia.try_into().ok()?))
}

fn u32_em(bytes: &[u8], deslocamento: usize) -> Option<u32> {
    let fatia = bytes.get(deslocamento..deslocamento + 4)?;
    Some(u32::from_le_bytes(fatia.try_into().ok()?))
}

/// Interpreta uma entrada da tabela.
///
/// Devolve `None` para uma entrada não usada, que é como a GPT marca um
/// espaço livre no vetor: GUID de tipo todo zero. Ela não é erro — o vetor
/// tem 128 entradas e um disco costuma usar duas.
pub fn ler_entrada(bytes: &[u8]) -> Option<Particao> {
    let guid = bytes.get(entrada::TIPO..entrada::TIPO + 16)?;
    if guid.iter().all(|b| *b == 0) {
        return None;
    }

    let primeiro = u64_em(bytes, entrada::PRIMEIRO)?;
    let ultimo = u64_em(bytes, entrada::ULTIMO)?;
    // O último é inclusive. Uma entrada com o último antes do primeiro é uma
    // tabela dizendo algo impossível, e a subtração daria a volta.
    let setores = ultimo.checked_sub(primeiro)?.checked_add(1)?;

    Some(Particao {
        primeiro,
        setores,
        tipo: Tipo::do_guid(guid),
    })
}

/// Os campos do cabeçalho que a varredura usa para calcular endereços, já
/// conferidos.
pub(crate) struct Plano {
    entradas_em: u64,
    quantas: u32,
    tamanho: usize,
    /// Quantas entradas cabem num setor.
    por_setor: usize,
}

impl Plano {
    /// O setor onde mora a entrada de índice `indice`.
    ///
    /// A soma não dá a volta: [`planejar`] já provou que a maior delas cabe, e
    /// `indice` nunca passa de `quantas - 1`.
    fn setor_da(&self, indice: u32) -> u64 {
        self.entradas_em + u64::from(indice) / self.por_setor as u64
    }
}

/// Confere o cabeçalho antes de a varredura calcular endereço nenhum.
///
/// # Por que é uma função à parte, e visível
///
/// Porque a varredura precisa de um disco e esta conta não. Separada, ela
/// recebe da suíte os valores que nenhum disco desta máquina produz — e é
/// justamente com esses que ela tem de estar certa.
///
/// # A regra que estava escrita de um lado só
///
/// O tamanho da entrada já era conferido aqui, com um comentário dizendo por
/// quê: "sem isto, um tamanho absurdo faria a aritmética de deslocamento
/// apontar para qualquer lugar do buffer". Os outros dois campos do mesmo
/// cabeçalho, lidos na mesma função e usados na mesma conta, não eram.
///
/// Com `entradas_em` perto do fim do `u64`, a soma que escolhe o setor dá a
/// volta — silêncio antes de `overflow-checks` entrar no perfil de release, e
/// pânico do kernel depois dele. Nas duas épocas o cabeçalho deste módulo
/// prometia outra coisa: que a resposta a uma tabela corrompida seria a mesma
/// que a resposta a uma tabela ausente.
pub(crate) fn planejar(
    entradas_em: u64,
    quantas: u32,
    tamanho: usize,
) -> Result<Plano, &'static str> {
    // Uma entrada precisa caber num setor e ter os campos que lemos. Sem
    // isto, um tamanho absurdo faria a aritmética de deslocamento apontar
    // para qualquer lugar do buffer.
    if !(entrada::ULTIMO + 8..=crate::virtio::blk::TAMANHO_DO_SETOR).contains(&tamanho) {
        return Err("tamanho de entrada implausivel na GPT");
    }
    if quantas > MAX_ENTRADAS {
        return Err("entradas demais na GPT");
    }

    let por_setor = crate::virtio::blk::TAMANHO_DO_SETOR / tamanho;

    // O setor da última entrada é a maior conta que a varredura vai fazer. Se
    // ele não cabe num `u64`, o vetor começa fora de qualquer disco possível —
    // e o que a varredura leria seria o endereço que sobrou da volta.
    entradas_em
        .checked_add(u64::from(quantas.saturating_sub(1)) / por_setor as u64)
        .ok_or("o vetor de entradas da GPT comeca fora do disco")?;

    Ok(Plano {
        entradas_em,
        quantas,
        tamanho,
        por_setor,
    })
}

/// Lê a tabela do disco da máquina.
pub fn varrer() -> Result<Tabela, &'static str> {
    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];

    let resultado = crate::virtio::blk::com_o_disco(|d| d.ler_setor(CABECALHO_EM, &mut setor));
    let Some(resultado) = resultado else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    if &setor[..8] != ASSINATURA {
        return Err("o setor um nao traz o cabecalho da GPT");
    }

    let plano = planejar(
        u64_em(&setor, cabecalho::ENTRADAS_EM).ok_or("cabecalho truncado")?,
        u32_em(&setor, cabecalho::QUANTAS).ok_or("cabecalho truncado")?,
        u32_em(&setor, cabecalho::TAMANHO).ok_or("cabecalho truncado")? as usize,
    )?;

    let mut tabela = Tabela::vazia();
    let mut achadas = 0;
    let mut indice = 0u32;

    while indice < plano.quantas && achadas < MAX {
        let setor_da_entrada = plano.setor_da(indice);
        let resultado =
            crate::virtio::blk::com_o_disco(|d| d.ler_setor(setor_da_entrada, &mut setor));
        let Some(resultado) = resultado else {
            return Err("nao ha disco nesta maquina");
        };
        resultado?;

        // Todas as entradas que couberem neste setor, antes de ler o próximo.
        for dentro in 0..plano.por_setor {
            if indice >= plano.quantas || achadas >= MAX {
                break;
            }
            if let Some(particao) = ler_entrada(&setor[dentro * plano.tamanho..]) {
                tabela.particoes[achadas] = Some(particao);
                achadas += 1;
            }
            indice += 1;
        }
    }

    Ok(tabela)
}
