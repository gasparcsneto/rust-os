//! Btrfs, somente leitura.
//!
//! # Onde ele está
//!
//! No começo. Este módulo lê o superbloco e confere a soma dele; a árvore de
//! blocos, os diretórios e os arquivos vêm em cima disto, em etapas. O método
//! é o mesmo do driver xHCI: cada etapa é confirmada pelo canal do agente
//! antes de a seguinte ser escrita, porque mil linhas escritas às cegas são
//! mil linhas para depurar de uma vez.
//!
//! # O gabarito
//!
//! A imagem que este código lê foi montada por `mkfs.btrfs`, e
//! `btrfs inspect-internal dump-super` diz o que deveria estar em cada campo.
//! Quem confere o leitor não é quem o escreveu — é a mesma disciplina do
//! `llvm-readelf` sobre os ELFs de usuário e do `sgdisk` sobre a GPT.

pub mod crc32c;
pub mod folha;
pub mod pedacos;

extern crate alloc;

/// Onde o superbloco mora, contado do começo da partição.
///
/// Sessenta e quatro kilobytes. Não é o começo de propósito: o espaço antes
/// dele é onde um gerenciador de boot cabe sem tocar no sistema de arquivos.
/// Há cópias mais adiante no disco, que este módulo ainda não lê — elas
/// existem para quando a primeira estiver corrompida, e a resposta a isso
/// ainda é a mesma que a resposta a um sistema de arquivos ausente.
const SUPERBLOCO_EM: u64 = 64 * 1024;

/// Quanto o superbloco ocupa.
const TAMANHO_DO_SUPERBLOCO: usize = 4096;

/// O que os oito bytes do campo de identificação trazem.
const MAGICA: &[u8; 8] = b"_BHRfS_M";

/// Quantos bytes o campo de soma ocupa no começo do bloco.
///
/// Trinta e dois, para caber o maior algoritmo que o formato admite. O crc32c
/// usa os quatro primeiros e deixa o resto zerado — e a soma é calculada
/// sobre tudo **depois** deste campo, que é o detalhe que faz um leitor
/// ingênuo obter sempre o número errado.
const TAMANHO_DA_SOMA: usize = 32;

/// Deslocamentos dentro do superbloco.
///
/// Conferidos contra os bytes crus da imagem antes de virarem código: lendo
/// `u64` em 48 sai 65536, em 80 sai a raiz que o `dump-super` reporta, e em
/// 148 sai o tamanho de nó. Um deslocamento errado aqui produz números
/// plausíveis — endereços que existem, tamanhos que cabem — e um sistema de
/// arquivos que nunca acha nada.
mod campo {
    pub const BYTENR: usize = 48;
    pub const MAGICA: usize = 64;
    pub const GERACAO: usize = 72;
    pub const RAIZ: usize = 80;
    pub const RAIZ_DOS_PEDACOS: usize = 88;
    pub const TOTAL: usize = 112;
    pub const USADO: usize = 120;
    pub const TAMANHO_DE_SETOR: usize = 144;
    pub const TAMANHO_DE_NO: usize = 148;
    pub const TAMANHO_DO_VETOR_DE_PEDACOS: usize = 160;
    pub const TIPO_DE_SOMA: usize = 196;
    pub const NIVEL_DA_RAIZ: usize = 198;
    pub const NIVEL_DA_RAIZ_DOS_PEDACOS: usize = 199;
    pub const ROTULO: usize = 299;
    /// Onde começa o vetor de pedaços do sistema, logo depois do rótulo e do
    /// que vem com ele.
    pub const VETOR_DE_PEDACOS: usize = 811;
    pub const TAMANHO_DO_ROTULO: usize = 256;
}

/// O único tipo de soma que este leitor entende.
const SOMA_CRC32C: u16 = 0;

/// O que o superbloco diz sobre o sistema de arquivos.
#[derive(Clone, Copy)]
pub struct Superbloco {
    pub geracao: u64,
    /// Endereço **lógico** da raiz da árvore de raízes.
    pub raiz: u64,
    /// Endereço lógico da raiz da árvore de pedaços.
    ///
    /// É por ela que tudo começa: os endereços deste sistema de arquivos são
    /// lógicos, e traduzi-los para deslocamentos no disco exige a árvore de
    /// pedaços — que é descrita por um endereço lógico. O superbloco quebra a
    /// circularidade carregando um vetor com os pedaços necessários para
    /// alcançá-la.
    pub raiz_dos_pedacos: u64,
    pub nivel_da_raiz: u8,
    pub nivel_da_raiz_dos_pedacos: u8,
    pub total: u64,
    pub usado: u64,
    pub tamanho_de_setor: u32,
    pub tamanho_de_no: u32,
    pub tamanho_do_vetor_de_pedacos: u32,
}

/// Lê um `u64` little-endian de dentro de um buffer.
fn u64_em(bytes: &[u8], deslocamento: usize) -> u64 {
    let mut valor = [0u8; 8];
    valor.copy_from_slice(&bytes[deslocamento..deslocamento + 8]);
    u64::from_le_bytes(valor)
}

fn u32_em(bytes: &[u8], deslocamento: usize) -> u32 {
    let mut valor = [0u8; 4];
    valor.copy_from_slice(&bytes[deslocamento..deslocamento + 4]);
    u32::from_le_bytes(valor)
}

fn u16_em(bytes: &[u8], deslocamento: usize) -> u16 {
    u16::from_le_bytes([bytes[deslocamento], bytes[deslocamento + 1]])
}

/// Interpreta um superbloco já lido para a memória.
///
/// Separado da leitura de propósito: assim a suíte pode exercitá-lo sobre
/// bytes que ela mesma monta, inclusive os que não deveriam passar.
pub fn ler_superbloco(bloco: &[u8]) -> Result<Superbloco, &'static str> {
    if bloco.len() < TAMANHO_DO_SUPERBLOCO {
        return Err("o superbloco nao foi lido inteiro");
    }
    if &bloco[campo::MAGICA..campo::MAGICA + 8] != MAGICA {
        return Err("nao ha um superbloco btrfs aqui");
    }

    let tipo = u16_em(bloco, campo::TIPO_DE_SOMA);
    if tipo != SOMA_CRC32C {
        return Err("a soma de verificacao nao e crc32c");
    }

    // A soma cobre tudo **depois** do campo dela. Calcular sobre o bloco
    // inteiro daria um número que nunca bate, e o sintoma seria um sistema de
    // arquivos íntegro sendo recusado como corrompido.
    let gravada = u32_em(bloco, 0);
    let calculada = crc32c::somar(&bloco[TAMANHO_DA_SOMA..TAMANHO_DO_SUPERBLOCO]);
    if gravada != calculada {
        return Err("a soma do superbloco nao confere");
    }

    // O endereço que o próprio bloco diz ocupar. Um superbloco lido do lugar
    // errado pode ter magia e soma válidas — é uma das cópias — e este campo
    // é o que distingue "li a cópia certa" de "li alguma cópia".
    if u64_em(bloco, campo::BYTENR) != SUPERBLOCO_EM {
        return Err("o superbloco nao é o do comeco da particao");
    }

    Ok(Superbloco {
        geracao: u64_em(bloco, campo::GERACAO),
        raiz: u64_em(bloco, campo::RAIZ),
        raiz_dos_pedacos: u64_em(bloco, campo::RAIZ_DOS_PEDACOS),
        nivel_da_raiz: bloco[campo::NIVEL_DA_RAIZ],
        nivel_da_raiz_dos_pedacos: bloco[campo::NIVEL_DA_RAIZ_DOS_PEDACOS],
        total: u64_em(bloco, campo::TOTAL),
        usado: u64_em(bloco, campo::USADO),
        tamanho_de_setor: u32_em(bloco, campo::TAMANHO_DE_SETOR),
        tamanho_de_no: u32_em(bloco, campo::TAMANHO_DE_NO),
        tamanho_do_vetor_de_pedacos: u32_em(bloco, campo::TAMANHO_DO_VETOR_DE_PEDACOS),
    })
}

/// O rótulo do sistema de arquivos, como texto.
pub fn rotulo(bloco: &[u8]) -> &str {
    let cru = &bloco[campo::ROTULO..campo::ROTULO + campo::TAMANHO_DO_ROTULO];
    let fim = cru.iter().position(|b| *b == 0).unwrap_or(cru.len());
    core::str::from_utf8(&cru[..fim]).unwrap_or("")
}

/// Lê o superbloco da partição que começa no setor `primeiro`.
pub fn do_disco(primeiro: u64, bloco: &mut [u8]) -> Result<Superbloco, &'static str> {
    if bloco.len() < TAMANHO_DO_SUPERBLOCO {
        return Err("o buffer nao cabe um superbloco");
    }

    let setor = primeiro + SUPERBLOCO_EM / crate::virtio::blk::TAMANHO_DO_SETOR as u64;
    let resultado =
        crate::virtio::blk::com_o_disco(|d| d.ler(setor, &mut bloco[..TAMANHO_DO_SUPERBLOCO]));
    let Some(resultado) = resultado else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    ler_superbloco(bloco)
}

// ---------------------------------------------------------------------------
// Ler um nó por endereço lógico
// ---------------------------------------------------------------------------

/// Deslocamentos dentro do cabeçalho de um nó da árvore.
///
/// Os primeiros trinta e dois bytes são a soma, como no superbloco, e pela
/// mesma razão ela cobre o que vem **depois** deles.
mod no {
    pub const BYTENR: usize = 48;
    pub const GERACAO: usize = 80;
    pub const DONO: usize = 88;
    pub const ITENS: usize = 96;
    pub const NIVEL: usize = 100;
    pub const TAMANHO: usize = 101;
}

/// O que o cabeçalho de um nó diz sobre ele.
#[derive(Clone, Copy, Debug)]
pub struct CabecalhoDeNo {
    /// O endereço lógico que o próprio nó afirma ocupar.
    pub endereco: u64,
    pub geracao: u64,
    /// Qual árvore o contém.
    pub dono: u64,
    pub itens: u32,
    /// Zero é folha; acima disso, nó interno.
    pub nivel: u8,
}

/// Um sistema de arquivos Btrfs aberto: onde ele está e como traduzir.
pub struct Volume {
    /// O primeiro setor da partição, no disco.
    primeiro: u64,
    pub superbloco: Superbloco,
    pub mapa: pedacos::Mapa,
}

impl Volume {
    /// Lê o superbloco de uma partição e monta o mapa inicial.
    pub fn abrir(primeiro: u64) -> Result<Volume, &'static str> {
        let mut bloco = alloc::vec![0u8; TAMANHO_DO_SUPERBLOCO];
        let superbloco = do_disco(primeiro, &mut bloco)?;

        // O vetor de pedaços do sistema, que é o que quebra a circularidade.
        let tamanho = superbloco.tamanho_do_vetor_de_pedacos as usize;
        let fim = campo::VETOR_DE_PEDACOS + tamanho;
        if tamanho == 0 || fim > TAMANHO_DO_SUPERBLOCO {
            return Err("o vetor de pedacos do sistema nao cabe no superbloco");
        }
        let mapa = pedacos::do_vetor_do_sistema(&bloco[campo::VETOR_DE_PEDACOS..fim])?;

        let mut volume = Volume {
            primeiro,
            superbloco,
            mapa,
        };

        // O vetor do superbloco é só o bastante para alcançar a árvore de
        // pedaços. O mapa de verdade está nela, e sem ele os endereços de
        // metadados — onde moram as outras árvores — não traduzem.
        volume.completar_mapa()?;
        Ok(volume)
    }

    /// Acrescenta ao mapa os pedaços que a árvore de pedaços descreve.
    ///
    /// # O que muda depois disto
    ///
    /// A tradução deixa de ser identidade. No disco que o `xtask` monta, o
    /// pedaço de sistema começa no mesmo endereço lógico e físico — e o de
    /// **metadados** não: ele é lógico 30408704 e físico 38797312. Como as
    /// outras árvores moram em metadados, ler qualquer uma delas passa a
    /// exigir a aritmética de verdade.
    fn completar_mapa(&mut self) -> Result<(), &'static str> {
        let mut bloco = alloc::vec![0u8; self.superbloco.tamanho_de_no as usize];
        let cabecalho = self.ler_no(self.superbloco.raiz_dos_pedacos, &mut bloco)?;

        // Um nó interno significaria uma árvore de pedaços com mais de um
        // nível, que este leitor ainda não percorre. Recusar é melhor que
        // montar um mapa pela metade e descobrir na primeira tradução que
        // falta um pedaço.
        if cabecalho.nivel != 0 {
            return Err("a arvore de pedacos tem mais de um nivel");
        }

        for item in folha::itens(&bloco)? {
            let item = item?;
            if item.chave.tipo != folha::tipo::PEDACO {
                continue;
            }
            // O endereço lógico do pedaço é o `offset` da chave — o item em si
            // não o traz.
            let logico = item.chave.offset;
            // O vetor do superbloco já trouxe o pedaço de sistema. Repetí-lo
            // gastaria uma vaga do mapa e daria duas respostas iguais à mesma
            // pergunta.
            if self.mapa.traduzir(logico).is_some() {
                continue;
            }
            let (pedaco, _) = pedacos::ler_item(logico, item.dados)?;
            self.mapa.acrescentar(pedaco)?;
        }

        Ok(())
    }

    /// Lê um nó da árvore pelo endereço lógico dele.
    ///
    /// Confere três coisas, e as três são o que separa "leu bytes" de "leu o
    /// nó": a soma de verificação, o endereço que o nó afirma ocupar, e o
    /// tamanho do destino. O segundo é o que pega uma tradução errada — um
    /// nó lido do lugar errado tem soma válida, porque é um nó de verdade,
    /// só que outro.
    pub fn ler_no(&self, logico: u64, destino: &mut [u8]) -> Result<CabecalhoDeNo, &'static str> {
        let tamanho = self.superbloco.tamanho_de_no as usize;
        if destino.len() < tamanho {
            return Err("o destino nao cabe um no");
        }
        if !(no::TAMANHO..=crate::virtio::blk::MAIOR_LEITURA).contains(&tamanho) {
            return Err("o tamanho de no nao e um que este leitor saiba ler");
        }

        let fisico = self
            .mapa
            .traduzir(logico)
            .ok_or("o endereco logico nao cai em pedaco conhecido")?;

        let setor_da_particao = crate::virtio::blk::TAMANHO_DO_SETOR as u64;
        if !fisico.is_multiple_of(setor_da_particao) {
            return Err("o endereco traduzido nao cai em fronteira de setor");
        }

        let setor = self.primeiro + fisico / setor_da_particao;
        let resultado = crate::virtio::blk::com_o_disco(|d| d.ler(setor, &mut destino[..tamanho]));
        let Some(resultado) = resultado else {
            return Err("nao ha disco nesta maquina");
        };
        resultado?;

        let gravada = u32_em(destino, 0);
        let calculada = crc32c::somar(&destino[TAMANHO_DA_SOMA..tamanho]);
        if gravada != calculada {
            return Err("a soma do no nao confere");
        }

        let endereco = u64_em(destino, no::BYTENR);
        if endereco != logico {
            return Err("o no lido afirma estar em outro endereco");
        }

        Ok(CabecalhoDeNo {
            endereco,
            geracao: u64_em(destino, no::GERACAO),
            dono: u64_em(destino, no::DONO),
            itens: u32_em(destino, no::ITENS),
            nivel: destino[no::NIVEL],
        })
    }
}

/// O endereço lógico da raiz que um item de raiz descreve.
///
/// O item é um `btrfs_root_item`, uma struct grande de que só um campo
/// interessa aqui: o endereço do nó de topo da árvore. Ele vem depois de um
/// `btrfs_inode_item` embutido, que é o que põe o deslocamento em 176.
pub fn raiz_da_arvore(item: &[u8]) -> Option<u64> {
    const BYTENR: usize = 176;
    let fatia = item.get(BYTENR..BYTENR + 8)?;
    Some(u64::from_le_bytes(fatia.try_into().ok()?))
}
