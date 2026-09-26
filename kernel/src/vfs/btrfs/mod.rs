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

pub mod arvore;
pub mod crc32c;
pub mod folha;
pub mod interno;
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
        // A árvore de pedaços é percorrida como qualquer outra, e a descida
        // dela funciona antes de o mapa estar completo por construção: ela
        // mora inteira dentro do pedaço de **sistema**, que é justamente o
        // que o vetor do superbloco já trouxe. É a mesma circularidade que o
        // vetor quebra, e ela continua quebrada com mais de um nível.
        let mut novos = alloc::vec::Vec::new();
        let mut erro = None;

        self.percorrer(
            self.superbloco.raiz_dos_pedacos,
            folha::Chave {
                objeto: 0,
                tipo: 0,
                offset: 0,
            },
            |item| {
                if item.chave.tipo != folha::tipo::PEDACO {
                    return Passo::Segue;
                }
                // O endereço lógico do pedaço é o `offset` da chave — o item
                // em si não o traz.
                let logico = item.chave.offset;
                // O vetor do superbloco já trouxe o pedaço de sistema.
                // Repetí-lo gastaria uma vaga do mapa e daria duas respostas
                // iguais à mesma pergunta.
                if self.mapa.traduzir(logico).is_some() {
                    return Passo::Segue;
                }
                match pedacos::ler_item(logico, item.dados) {
                    Ok((pedaco, _)) => {
                        novos.push(pedaco);
                        Passo::Segue
                    }
                    // O mapa precisa ficar completo ou não ficar: um pedaço
                    // que não se sabe ler vira um endereço lógico que traduz
                    // errado depois, longe daqui.
                    Err(motivo) => {
                        erro = Some(motivo);
                        Passo::Para
                    }
                }
            },
        )?;

        if let Some(motivo) = erro {
            return Err(motivo);
        }
        // Os pedaços entram no mapa **depois** do percurso: acrescentar ali
        // dentro exigiria emprestar o volume como mutável enquanto ele
        // próprio conduz a leitura.
        for pedaco in novos {
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

/// O que fazer depois de olhar um item.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Passo {
    /// Continua para o próximo item, atravessando folhas se preciso.
    Segue,
    /// Encerra o percurso aqui.
    Para,
}

/// Quantas folhas um percurso pode visitar antes de desistir.
///
/// Não é um limite do formato: é um teto contra uma árvore corrompida que
/// leve o percurso a andar para sempre. A cada folha a chave procurada cresce
/// estritamente, então um percurso são termina sozinho; este número é o que
/// garante que um insano também termine, e com um erro que diz o que houve.
///
/// Oito mil folhas de 4 KiB cobrem trinta e dois megabytes de metadados —
/// muito acima de qualquer coisa que este kernel monte, e ainda assim um
/// número, e não "até acabar".
const MAX_FOLHAS: usize = 8192;

impl Volume {
    /// Chama `f` para cada item da árvore, em ordem de chave, a partir de
    /// `de`.
    ///
    /// # Por que isto substituiu "ler a folha"
    ///
    /// Porque a árvore tem mais de um nível assim que o sistema de arquivos
    /// passa de um punhado de arquivos, e um leitor de uma folha só devolve
    /// os itens do primeiro nó e nada dos outros — um sistema de arquivos
    /// que parece funcionar e esconde a maior parte do conteúdo. Era o
    /// limite declarado deste leitor, e é o que sai aqui.
    ///
    /// # Como o percurso atravessa folhas
    ///
    /// Descendo de novo. Ao esgotar uma folha, ele pega a **última chave**
    /// dela, calcula a sucessora e desce da raiz outra vez procurando por
    /// ela. É uma leitura de nó a mais por folha, por nível da árvore.
    ///
    /// A alternativa é o que o Btrfs de verdade faz: guardar o caminho
    /// inteiro — um nó por nível, com a fatia escolhida em cada um — e subir
    /// só o necessário para achar o irmão à direita. É mais rápido e custa
    /// um buffer de nó **por nível**, vivo durante todo o percurso.
    ///
    /// A escolha aqui é a barata em memória: um buffer só. Com uma árvore de
    /// dois níveis, o preço é uma leitura extra por folha, e as leituras de
    /// nó interno vêm do mesmo punhado de blocos que o disco entrega
    /// rapidamente. O dia em que a profundidade crescer, ou em que uma
    /// medição mostrar o custo, o caminho guardado entra — e entra sem mudar
    /// nenhum chamador, porque todos passam por aqui.
    /// # O que o número devolvido serve para responder
    ///
    /// Quantas folhas foram lidas. É o que permite a um caso afirmar que a
    /// travessia aconteceu: contar **itens** não serve, porque quantos cabem
    /// numa folha depende do tamanho de cada um, e um teto teórico é folgado
    /// demais para reprovar um percurso que parou na primeira.
    pub fn percorrer<F>(&self, raiz: u64, de: folha::Chave, mut f: F) -> Result<usize, &'static str>
    where
        F: FnMut(&folha::Item) -> Passo,
    {
        let mut no = alloc::vec![0u8; self.superbloco.tamanho_de_no as usize];
        let mut procurada = Some(de);
        let mut folhas = 0usize;

        while let Some(alvo) = procurada {
            folhas += 1;
            if folhas > MAX_FOLHAS {
                return Err("o percurso pela arvore nao termina");
            }

            self.descer_ate_a_folha(raiz, alvo, &mut no)?;

            // A sucessora é calculada **antes** de percorrer os itens, porque
            // `f` pode parar no meio e a folha seguinte deixa de interessar.
            // Calcular depois daria na mesma e obrigaria a repetir a leitura
            // do cabeçalho nos dois caminhos de saída.
            let ultima = interno::ultima_chave_da_folha(&no);
            procurada = match ultima {
                // A folha acabou antes do alvo: não há mais nada à direita.
                // Acontece na última folha da árvore, quando o alvo passou de
                // todas as chaves que existem.
                Some(ultima) if ultima >= alvo => ultima.sucessora(),
                _ => None,
            };

            for item in folha::itens(&no)? {
                let item = item?;
                // Uma folha traz chaves anteriores ao alvo sempre que ele cai
                // no meio dela — que é o caso comum da primeira descida.
                // Entregá-las seria começar o percurso antes de onde quem
                // chamou pediu.
                if item.chave < alvo {
                    continue;
                }
                if f(&item) == Passo::Para {
                    return Ok(folhas);
                }
            }
        }

        Ok(folhas)
    }

    /// Desce da raiz até a folha onde `alvo` está, ou estaria.
    ///
    /// # O que a descida confere, e por quê
    ///
    /// Que o nível cai de exatamente um a cada passo. É a invariante que
    /// distingue uma árvore de um grafo: um nó que apontasse para si mesmo,
    /// ou para um irmão, faria a descida girar — e girar lendo do disco, com
    /// a soma de verificação conferindo em toda volta, porque cada nó é um nó
    /// de verdade.
    ///
    /// O teto de níveis existe pelo mesmo motivo, um degrau acima: ele pega o
    /// caso em que os níveis até caem, mas a árvore é mais funda do que o
    /// formato permite.
    ///
    /// # Nenhum caso derruba a conferência de nível, e não há como escrever
    /// um
    ///
    /// Medido, apagando-a: a suíte inteira passa. Não é falha dos casos —
    /// para exercitá-la seria preciso um nó interno apontando para outro do
    /// nível errado, e um nó desses não é algo que se forje: ele teria de
    /// estar **no disco**, com a soma de verificação certa, dentro de um
    /// pedaço mapeado, apontado por uma árvore que o `mkfs.btrfs` não
    /// produz.
    ///
    /// Ela fica porque o custo é uma comparação e o que ela evita é um laço
    /// de leituras de disco dentro do kernel — e porque o teto de níveis
    /// sozinho não a cobre: uma árvore que alternasse entre dois nós do
    /// mesmo nível terminaria no teto, sim, mas depois de oito idas ao disco
    /// e com a mensagem errada.
    fn descer_ate_a_folha(
        &self,
        raiz: u64,
        alvo: folha::Chave,
        no: &mut [u8],
    ) -> Result<(), &'static str> {
        let mut endereco = raiz;
        let mut esperado: Option<u8> = None;

        for _ in 0..=interno::MAX_NIVEL {
            let cabecalho = self.ler_no(endereco, no)?;

            if let Some(esperado) = esperado
                && cabecalho.nivel != esperado
            {
                return Err("a arvore aponta para um no do nivel errado");
            }
            if cabecalho.nivel == 0 {
                return Ok(());
            }

            endereco = interno::descer_para(no, alvo)?;
            esperado = Some(cabecalho.nivel - 1);
        }

        Err("a arvore e mais funda do que o formato permite")
    }

    /// O primeiro item com este objeto e tipo, copiado para um vetor.
    ///
    /// # Por que copiar, e não devolver uma fatia
    ///
    /// Porque a fatia apontaria para dentro do buffer da folha, que morre com
    /// o percurso. Manter o buffer vivo obrigaria quem chama a carregá-lo
    /// junto, e o item que interessa tem cento e sessenta bytes num inode e
    /// alguns milhares numa extensão embutida — uma cópia que não aparece em
    /// medição nenhuma ao lado da ida ao disco que a precedeu.
    pub fn achar(
        &self,
        raiz: u64,
        objeto: u64,
        tipo: u8,
    ) -> Result<Option<alloc::vec::Vec<u8>>, &'static str> {
        let mut achado = None;
        self.percorrer(raiz, folha::Chave::primeira_de(objeto, tipo), |item| {
            // Como o percurso é em ordem de chave, o primeiro item que sair
            // do par (objeto, tipo) garante que não há mais nenhum: parar
            // aqui é o que evita varrer a árvore inteira atrás de algo que
            // já se sabe que acabou.
            if item.chave.objeto != objeto || item.chave.tipo != tipo {
                return Passo::Para;
            }
            achado = Some(item.dados.to_vec());
            Passo::Para
        })?;
        Ok(achado)
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

// ---------------------------------------------------------------------------
// O Btrfs como sistema de arquivos do VFS
// ---------------------------------------------------------------------------

impl Volume {
    /// Acha a árvore de arquivos entre as raízes que a árvore de raízes lista.
    ///
    /// Devolve o endereço lógico do nó de topo dela e o número do inode que é
    /// o diretório raiz — os dois vêm do mesmo item, e separá-los seria ler a
    /// árvore duas vezes.
    pub fn raiz_dos_arquivos(&self) -> Result<(u64, u64), &'static str> {
        let item = self
            .achar(
                self.superbloco.raiz,
                arvore::ARVORE_DE_ARQUIVOS,
                folha::tipo::RAIZ,
            )?
            .ok_or("nao ha arvore de arquivos neste sistema de arquivos")?;

        let endereco = raiz_da_arvore(&item).ok_or("item de raiz truncado")?;
        let diretorio = diretorio_da_raiz(&item).ok_or("item de raiz truncado")?;
        Ok((endereco, diretorio))
    }

    /// Quantos níveis a árvore que começa em `raiz` tem acima das folhas.
    ///
    /// Existe para a suíte, e por um motivo que não é curiosidade: os casos
    /// que exercitam a descida só valem se a árvore **tiver** por onde
    /// descer. Sem esta pergunta, uma mudança na imagem que voltasse a
    /// caber numa folha faria todos eles passarem sem testar nada.
    pub fn nivel_da_arvore(&self, raiz: u64) -> Result<u8, &'static str> {
        let mut no = alloc::vec![0u8; self.superbloco.tamanho_de_no as usize];
        Ok(self.ler_no(raiz, &mut no)?.nivel)
    }
}

/// O inode que é o diretório raiz de uma árvore, dentro do item de raiz.
fn diretorio_da_raiz(item: &[u8]) -> Option<u64> {
    const DIRETORIO: usize = 168;
    let fatia = item.get(DIRETORIO..DIRETORIO + 8)?;
    Some(u64::from_le_bytes(fatia.try_into().ok()?))
}

/// Um sistema de arquivos Btrfs pronto para o VFS.
pub struct Sistema {
    volume: Volume,
    /// O endereço lógico da folha da árvore de arquivos.
    raiz: u64,
    /// O inode do diretório raiz.
    diretorio: u64,
}

impl Sistema {
    /// Abre a partição de dados do disco como sistema de arquivos.
    pub fn abrir(primeiro: u64) -> Result<Sistema, &'static str> {
        let volume = Volume::abrir(primeiro)?;
        let (raiz, diretorio) = volume.raiz_dos_arquivos()?;
        Ok(Sistema {
            volume,
            raiz,
            diretorio,
        })
    }

    /// O nó do VFS para um inode, lendo o item dele.
    fn no_de(&self, numero: u64) -> Result<crate::vfs::No, crate::vfs::Erro> {
        let dados = self
            .volume
            .achar(self.raiz, numero, arvore::tipo::INODE)
            .map_err(|_| crate::vfs::Erro::DoDispositivo)?
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;
        let inode = arvore::ler_inode(&dados).ok_or(crate::vfs::Erro::DoDispositivo)?;

        let tipo = match inode.especie {
            arvore::Especie::Arquivo => crate::vfs::Tipo::Arquivo,
            arvore::Especie::Diretorio => crate::vfs::Tipo::Diretorio,
            // Um link simbólico ou um nó de dispositivo. O VFS não tem como
            // descrevê-los, e inventar um tipo seria pior que dizer que não
            // se sabe o que é.
            arvore::Especie::Outro => return Err(crate::vfs::Erro::NaoEncontrado),
        };

        Ok(crate::vfs::No {
            tipo,
            id: numero,
            tamanho: inode.tamanho,
        })
    }
}

impl crate::vfs::SistemaDeArquivos for Sistema {
    fn raiz(&self) -> crate::vfs::No {
        crate::vfs::No {
            tipo: crate::vfs::Tipo::Diretorio,
            id: self.diretorio,
            tamanho: 0,
        }
    }

    fn procurar(
        &self,
        dir: &crate::vfs::No,
        nome: &str,
    ) -> Result<crate::vfs::No, crate::vfs::Erro> {
        let entrada = arvore::procurar(&self.volume, self.raiz, dir.id, nome)
            .map_err(|_| crate::vfs::Erro::DoDispositivo)?
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;

        // Uma entrada pode apontar para a raiz de outra árvore — é assim que
        // um subvolume aparece dentro de um diretório. Seguir aquilo como se
        // fosse inode leria o item errado, e este leitor não monta subvolume.
        //
        // Não é falsificável pela imagem de teste: o `xtask` não cria
        // subvolume, e um `mkfs.btrfs --rootdir` também não. Fica escrito
        // aqui em vez de parecer coberto. O dia em que a imagem tiver um
        // subvolume, este é o caso que passa a existir.
        if entrada.tipo_da_chave != arvore::tipo::INODE {
            return Err(crate::vfs::Erro::NaoEncontrado);
        }

        self.no_de(entrada.objeto)
    }

    fn ler(
        &self,
        no: &crate::vfs::No,
        deslocamento: u64,
        destino: &mut [u8],
    ) -> Result<usize, crate::vfs::Erro> {
        let dados = self
            .volume
            .achar(self.raiz, no.id, arvore::tipo::EXTENSAO)
            .map_err(|_| crate::vfs::Erro::DoDispositivo)?
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;
        let conteudo = arvore::ler_extensao(&dados).map_err(|_| crate::vfs::Erro::DoDispositivo)?;

        // O que ainda falta ler do arquivo, que é o teto de qualquer extensão.
        let restante = no.tamanho.saturating_sub(deslocamento) as usize;
        if restante == 0 {
            return Ok(0);
        }
        let quanto = destino.len().min(restante);

        match conteudo {
            arvore::Conteudo::Embutido { em, quantos } => {
                let inicio = em + deslocamento as usize;
                let disponivel = quantos.saturating_sub(deslocamento as usize);
                let quanto = quanto.min(disponivel);
                let fatia = dados
                    .get(inicio..inicio + quanto)
                    .ok_or(crate::vfs::Erro::DoDispositivo)?;
                destino[..quanto].copy_from_slice(fatia);
                Ok(quanto)
            }

            arvore::Conteudo::Buraco { quantos } => {
                // Um buraco lê como zeros. O destino já pode trazer qualquer
                // coisa de quem chamou, então zerar é obrigatório.
                //
                // Este braço não é falsificável pela imagem de teste, e está
                // escrito aqui em vez de parecer coberto: o `mkfs.btrfs
                // --rootdir` materializa os buracos dos arquivos que copia —
                // um arquivo esparso entra na imagem com os zeros gravados —,
                // então nenhum arquivo daqui tem extensão com endereço zero.
                //
                // O que a suíte cobre é a **classificação**: o caso sintético
                // exige que um endereço zero vire `Buraco` em vez de virar um
                // endereço para traduzir. É a metade que decide se estes
                // zeros são escritos ou se o arquivo recebe os bytes que
                // morarem no endereço lógico zero.
                // O buraco também tem um tamanho, e ele manda: zerar além do
                // fim da extensão inventaria conteúdo para uma faixa do
                // arquivo sobre a qual esta extensão não diz nada.
                let disponivel = quantos.saturating_sub(deslocamento) as usize;
                let quanto = quanto.min(disponivel);
                destino[..quanto].fill(0);
                Ok(quanto)
            }

            arvore::Conteudo::Normal { endereco, quantos } => {
                let disponivel = quantos.saturating_sub(deslocamento) as usize;
                let quanto = quanto.min(disponivel);
                if quanto == 0 {
                    return Ok(0);
                }

                // Uma ida ao disco por vez, do tamanho que o driver monta.
                let por_vez = crate::virtio::blk::MAIOR_LEITURA;
                let logico = endereco + deslocamento;
                let setor_em_bytes = crate::virtio::blk::TAMANHO_DO_SETOR as u64;

                // A leitura precisa começar numa fronteira de setor: o driver
                // lê setores inteiros. O que sobra antes do ponto pedido é
                // lido junto e descartado.
                let alinhado = logico - (logico % setor_em_bytes);
                let dentro = (logico - alinhado) as usize;
                let bytes = (dentro + quanto).min(por_vez);

                let fisico = self
                    .volume
                    .mapa
                    .traduzir(alinhado)
                    .ok_or(crate::vfs::Erro::DoDispositivo)?;

                let mut bruto = alloc::vec![0u8; bytes.div_ceil(
                    crate::virtio::blk::TAMANHO_DO_SETOR
                ) * crate::virtio::blk::TAMANHO_DO_SETOR];
                let setor = self.volume.primeiro + fisico / setor_em_bytes;
                let resultado = crate::virtio::blk::com_o_disco(|d| d.ler(setor, &mut bruto));
                resultado
                    .ok_or(crate::vfs::Erro::DoDispositivo)?
                    .map_err(|_| crate::vfs::Erro::DoDispositivo)?;

                let veio = (bruto.len() - dentro).min(quanto);
                destino[..veio].copy_from_slice(&bruto[dentro..dentro + veio]);
                Ok(veio)
            }
        }
    }

    fn listar(
        &self,
        dir: &crate::vfs::No,
        indice: usize,
    ) -> Result<Option<crate::vfs::Entrada>, crate::vfs::Erro> {
        let mut atual = 0usize;
        let mut achada = None;

        arvore::listar(&self.volume, self.raiz, dir.id, |entrada| {
            if atual == indice && achada.is_none() {
                achada = Some((
                    alloc::string::String::from_utf8_lossy(entrada.nome).into_owned(),
                    entrada.objeto,
                    entrada.tipo_da_chave,
                ));
            }
            atual += 1;
            // Parar na entrada pedida é o que mantém o custo de listar um
            // diretório proporcional ao índice, e não ao tamanho da árvore:
            // sem isto, cada chamada varreria todas as folhas até o fim.
            achada.is_none()
        })
        .map_err(|_| crate::vfs::Erro::DoDispositivo)?;

        let Some((nome, objeto, tipo_da_chave)) = achada else {
            return Ok(None);
        };
        if tipo_da_chave != arvore::tipo::INODE {
            return Ok(Some(crate::vfs::Entrada {
                nome,
                tipo: crate::vfs::Tipo::Diretorio,
            }));
        }

        let no = self.no_de(objeto)?;
        Ok(Some(crate::vfs::Entrada {
            nome,
            tipo: no.tipo,
        }))
    }
}
