//! O pedaço do ELF64 que um carregador precisa entender.
//!
//! # O que um carregador lê, e o que ele ignora
//!
//! Um ELF tem duas visões do mesmo arquivo: a de **seções**, que interessa ao
//! ligador e ao depurador, e a de **segmentos**, que diz o que vai para a
//! memória. Um carregador só olha a segunda — e é por isso que este módulo
//! não sabe o que é uma seção, e o kernel do Duke boota com `e_shoff` zerado
//! nos programas de exemplo sem que nada reclame.
//!
//! # A regra que vale para cada campo
//!
//! O arquivo veio de um disco, e um disco é entrada não confiável — nem por
//! malícia, que num bootloader é uma preocupação distante, mas por um bit
//! trocado ou por um build pela metade. Cada campo é conferido antes de virar
//! decisão, e cada soma é feita com `checked_add`: um `p_offset + p_filesz`
//! que transborde produziria uma fatia que *parece* pequena e aponta para
//! qualquer lugar.
//!
//! É a mesma disciplina que o carregador de ELF do kernel já aplica aos
//! programas de usuário. A diferença é o que está em jogo: lá um arquivo
//! malformado mata um processo; aqui ele mata o boot.

/// Os sete primeiros bytes de todo ELF64 little-endian.
///
/// `\x7fELF`, depois classe 2 (64 bits), codificação 1 (little-endian) e
/// versão 1. Conferir os sete juntos é mais barato e mais claro que quatro
/// comparações, e erra menos.
///
/// # Por que sete, e não oito
///
/// O oitavo é o ABI (`EI_OSABI`), e ele não é assinatura: dois valores são
/// legítimos para o kernel. Zero, o System V, é o que o ligador grava
/// normalmente; três, o GNU, é o que o `lld` grava quando uma seção pede
/// para ser retida (`SHF_GNU_RETAIN`) — o que todo `#[used]` pede. Esta
/// constante já teve oito bytes, com o zero no fim, e o primeiro `#[used]`
/// no kernel o deixou sem boot, com "não é um ELF64 little-endian" na tela:
/// um arquivo perfeitamente válido, recusado por um campo que não muda nada
/// para um executável sem intérprete. Achado por acaso, medindo outra coisa.
const IDENTIFICACAO: [u8; 7] = [0x7F, b'E', b'L', b'F', 2, 1, 1];

/// O byte do ABI, e os dois que o kernel pode trazer — ver [`IDENTIFICACAO`].
const ABI: usize = 7;
const ABI_SYSTEM_V: u8 = 0;
const ABI_GNU: u8 = 3;

/// Os tipos de arquivo que um carregador aceita.
mod tipo {
    /// Executável de endereço fixo.
    pub const EXECUTAVEL: u16 = 2;
    /// Objeto compartilhado — que é o que um executável independente de
    /// posição é, e é como o kernel do Duke é ligado.
    pub const COMPARTILHADO: u16 = 3;
}

/// Deslocamentos dentro do cabeçalho ELF64.
mod cabecalho {
    pub const TIPO: usize = 16;
    pub const MAQUINA: usize = 18;
    pub const ENTRADA: usize = 24;
    pub const PROGRAMAS_EM: usize = 32;
    pub const TAMANHO_DO_PROGRAMA: usize = 54;
    pub const QUANTOS_PROGRAMAS: usize = 56;
    pub const TAMANHO: usize = 64;
}

/// Deslocamentos dentro de um cabeçalho de programa (segmento).
mod programa {
    pub const TIPO: usize = 0;
    pub const PERMISSOES: usize = 4;
    pub const NO_ARQUIVO: usize = 8;
    pub const ENDERECO: usize = 16;
    pub const TAMANHO_NO_ARQUIVO: usize = 32;
    pub const TAMANHO_NA_MEMORIA: usize = 40;
    pub const ALINHAMENTO: usize = 48;
    pub const TAMANHO: usize = 56;
}

/// `PT_LOAD`: o único tipo de segmento que vai para a memória.
const CARREGAVEL: u32 = 1;
/// `PT_DYNAMIC`: onde o ligador dinâmico procura o que ainda falta resolver.
const DINAMICO: u32 = 2;

/// As etiquetas da seção dinâmica que um carregador de PIE precisa.
mod etiqueta {
    /// Fim da lista.
    pub const FIM: u64 = 0;
    /// Quantos bytes de relocações da PLT existem.
    pub const BYTES_DA_PLT: u64 = 2;
    /// Onde a tabela de relocações começa, em endereço virtual.
    pub const RELA: u64 = 7;
    /// Quantos bytes ela tem.
    pub const RELA_BYTES: u64 = 8;
    /// Quanto ocupa cada entrada dela.
    pub const RELA_ENTRADA: u64 = 9;
}

/// Quanto ocupa uma entrada `Elf64_Rela`.
pub const TAMANHO_DA_RELOCACAO: usize = 24;

/// As permissões de um segmento, como bits.
pub mod permissao {
    pub const EXECUTAR: u32 = 1;
    pub const ESCREVER: u32 = 2;
    pub const LER: u32 = 4;
}

/// Um segmento que precisa ir para a memória.
#[derive(Clone, Copy, Debug)]
pub struct Segmento {
    /// Onde os bytes estão no arquivo.
    pub no_arquivo: u64,
    /// Onde eles querem morar, antes de qualquer deslocamento de base.
    pub endereco: u64,
    /// Quantos bytes o arquivo traz.
    pub tamanho_no_arquivo: u64,
    /// Quantos bytes o segmento ocupa na memória. A diferença é a `.bss`, e o
    /// carregador tem de entregá-la zerada.
    pub tamanho_na_memoria: u64,
    pub permissoes: u32,
    pub alinhamento: u64,
}

impl Segmento {
    /// Quantos bytes além do arquivo o segmento pede — a `.bss`.
    pub fn zeros(&self) -> u64 {
        self.tamanho_na_memoria
            .saturating_sub(self.tamanho_no_arquivo)
    }
}

/// O que o carregador extraiu do arquivo.
pub struct Imagem<'a> {
    bytes: &'a [u8],
    /// O endereço de entrada, no mesmo espaço dos `endereco` dos segmentos.
    pub entrada: u64,
    pub maquina: u16,
    /// Se o arquivo é independente de posição.
    ///
    /// O kernel do Duke é: ele é ligado a partir do zero e a base vem de
    /// fora. Um executável de endereço fixo traz a base dentro dele, e somar
    /// um deslocamento a ela daria um endereço que ninguém pediu.
    pub independente_de_posicao: bool,
    programas_em: u64,
    tamanho_do_programa: usize,
    quantos_programas: usize,
}

fn u16_em(bytes: &[u8], em: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(em..em + 2)?.try_into().ok()?))
}

fn u32_em(bytes: &[u8], em: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(em..em + 4)?.try_into().ok()?))
}

fn u64_em(bytes: &[u8], em: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(em..em + 8)?.try_into().ok()?))
}

// Quais métodos têm consumidor depende do alvo: o iniciador do x86 já copia
// e reloca a imagem, e o do ARM ainda só a confere. Anotar aqui é mais
// honesto que inventar um chamador só para o build ficar limpo — e some
// sozinho quando o salto do ARM chegar.
#[allow(dead_code)]
impl<'a> Imagem<'a> {
    /// Confere o cabeçalho e prepara a leitura dos segmentos.
    pub fn abrir(bytes: &'a [u8]) -> Result<Imagem<'a>, &'static str> {
        if bytes.len() < cabecalho::TAMANHO {
            return Err("o arquivo e menor que um cabecalho ELF");
        }
        if bytes[..IDENTIFICACAO.len()] != IDENTIFICACAO {
            return Err("nao e um ELF64 little-endian");
        }
        if !matches!(bytes[ABI], ABI_SYSTEM_V | ABI_GNU) {
            return Err("o ELF e de um ABI que o kernel nao usa");
        }

        let tipo = u16_em(bytes, cabecalho::TIPO).ok_or("cabecalho truncado")?;
        let independente_de_posicao = match tipo {
            tipo::EXECUTAVEL => false,
            tipo::COMPARTILHADO => true,
            // Um objeto relocável ou um core dump. Nenhum dos dois é
            // executável, e tratá-los como tal carregaria bytes que não são
            // um programa.
            _ => return Err("o ELF nao e executavel nem independente de posicao"),
        };

        let tamanho_do_programa =
            u16_em(bytes, cabecalho::TAMANHO_DO_PROGRAMA).ok_or("cabecalho truncado")? as usize;
        // O tamanho vem do arquivo, e é o passo com que a tabela é
        // percorrida. Menor que o formato faria os campos sairem
        // sobrepostos; zero faria o laço ler o mesmo cabeçalho para sempre.
        //
        // **Esta recusa é falsificável e a suíte a exercita** — há um caso que
        // põe um kernel com `e_phentsize` de oito bytes na ESP e exige que o
        // iniciador o rejeite com esta mensagem.
        //
        // O **passo** em si não é. Todo ELF64 que este ferramental produz tem
        // `e_phentsize` igual a 56, que é exatamente o tamanho do formato, e
        // por isso trocar `self.tamanho_do_programa` pela constante não
        // reprova nada: medido por mutação. Ele é lido do arquivo mesmo assim
        // porque o formato permite que difira — e porque o mesmo engano no
        // mapa de memória da UEFI **não** é hipótese: lá o firmware declara
        // descritores de 48 bytes contra 40 do formato, e usar a constante lê
        // o mapa inteiro deslocado.
        if tamanho_do_programa < programa::TAMANHO {
            return Err("os cabecalhos de programa sao menores que o formato");
        }

        Ok(Imagem {
            bytes,
            entrada: u64_em(bytes, cabecalho::ENTRADA).ok_or("cabecalho truncado")?,
            maquina: u16_em(bytes, cabecalho::MAQUINA).ok_or("cabecalho truncado")?,
            independente_de_posicao,
            programas_em: u64_em(bytes, cabecalho::PROGRAMAS_EM).ok_or("cabecalho truncado")?,
            tamanho_do_programa,
            quantos_programas: u16_em(bytes, cabecalho::QUANTOS_PROGRAMAS)
                .ok_or("cabecalho truncado")? as usize,
        })
    }

    /// Percorre os segmentos que vão para a memória.
    ///
    /// Os que não são `PT_LOAD` são pulados em silêncio: um `PT_NOTE` ou um
    /// `PT_GNU_STACK` descreve o arquivo, não o que vai para a RAM.
    pub fn segmentos(&self) -> impl Iterator<Item = Result<Segmento, &'static str>> + use<'_, 'a> {
        self.de_tipo(CARREGAVEL)
    }

    /// O segmento dinâmico, se houver.
    ///
    /// Um executável independente de posição traz um, e é nele que está a
    /// tabela de relocações. Um de endereço fixo não precisa de nenhum.
    pub fn dinamica(&self) -> Result<Option<Segmento>, &'static str> {
        self.de_tipo(DINAMICO).next().transpose()
    }

    fn de_tipo(
        &self,
        tipo: u32,
    ) -> impl Iterator<Item = Result<Segmento, &'static str>> + use<'_, 'a> {
        (0..self.quantos_programas).filter_map(move |i| self.programa(i, tipo).transpose())
    }

    fn programa(&self, i: usize, procurado: u32) -> Result<Option<Segmento>, &'static str> {
        let em = self
            .programas_em
            .checked_add((i * self.tamanho_do_programa) as u64)
            .and_then(|em| usize::try_from(em).ok())
            .ok_or("a tabela de programas sai do arquivo")?;
        let cru = self
            .bytes
            .get(em..em.checked_add(programa::TAMANHO).ok_or("transbordo")?)
            .ok_or("a tabela de programas sai do arquivo")?;

        if u32_em(cru, programa::TIPO).ok_or("programa truncado")? != procurado {
            return Ok(None);
        }

        let segmento = Segmento {
            no_arquivo: u64_em(cru, programa::NO_ARQUIVO).ok_or("programa truncado")?,
            endereco: u64_em(cru, programa::ENDERECO).ok_or("programa truncado")?,
            tamanho_no_arquivo: u64_em(cru, programa::TAMANHO_NO_ARQUIVO)
                .ok_or("programa truncado")?,
            tamanho_na_memoria: u64_em(cru, programa::TAMANHO_NA_MEMORIA)
                .ok_or("programa truncado")?,
            permissoes: u32_em(cru, programa::PERMISSOES).ok_or("programa truncado")?,
            alinhamento: u64_em(cru, programa::ALINHAMENTO).ok_or("programa truncado")?,
        };

        // Um segmento que pede menos memória do que traz do arquivo é
        // contraditório: os bytes que sobram não teriam para onde ir.
        if segmento.tamanho_na_memoria < segmento.tamanho_no_arquivo {
            return Err("um segmento traz mais do arquivo do que ocupa na memoria");
        }
        // E os bytes dele precisam existir no arquivo.
        let fim = segmento
            .no_arquivo
            .checked_add(segmento.tamanho_no_arquivo)
            .ok_or("um segmento transborda no arquivo")?;
        if fim > self.bytes.len() as u64 {
            return Err("um segmento aponta para alem do fim do arquivo");
        }

        Ok(Some(segmento))
    }

    /// Onde, no arquivo, mora um endereço virtual carregado.
    ///
    /// Serve para confrontar o que foi para a memória com o que veio do
    /// disco. Devolve `None` quando o endereço cai num pedaço que o arquivo
    /// não traz — a `.bss`, por exemplo, que existe na memória e não no
    /// arquivo.
    pub fn no_arquivo(&self, virtual_: u64) -> Result<Option<u64>, &'static str> {
        for segmento in self.segmentos() {
            let s = segmento?;
            if virtual_ >= s.endereco && virtual_ - s.endereco < s.tamanho_no_arquivo {
                return Ok(Some(s.no_arquivo + (virtual_ - s.endereco)));
            }
        }
        Ok(None)
    }

    /// Um byte do arquivo, pelo deslocamento.
    pub fn byte(&self, em: u64) -> Result<u8, &'static str> {
        let em = usize::try_from(em).map_err(|_| "deslocamento grande demais")?;
        self.bytes
            .get(em)
            .copied()
            .ok_or("o deslocamento esta fora do arquivo")
    }

    /// Onde está a tabela de relocações desta imagem.
    ///
    /// Um atalho sobre [`relocacoes`] que evita ao chamador ter de alcançar
    /// os bytes crus do arquivo — que são privados de propósito: quem os
    /// tivesse na mão poderia recortar qualquer coisa deles sem passar pelas
    /// conferências de faixa que esta struct faz.
    pub fn relocacoes(&self, dinamica: &Segmento, menor: u64) -> Result<Relocacoes, &'static str> {
        relocacoes(
            self.bytes,
            menor,
            dinamica.endereco,
            dinamica.tamanho_no_arquivo,
        )
    }

    /// Um pedaço do arquivo, pelo deslocamento e pelo tamanho.
    ///
    /// Devolve `None` quando o pedaço sai do arquivo — que é a resposta
    /// certa: tudo aqui vem de um arquivo lido de um disco, e recortar
    /// memória vizinha porque um número veio grande demais é como um leitor
    /// de formato entrega o conteúdo de outra coisa como se fosse o pedido.
    pub fn fatia(&self, em: u64, quantos: usize) -> Option<&'a [u8]> {
        let de = usize::try_from(em).ok()?;
        self.bytes.get(de..de.checked_add(quantos)?)
    }

    /// Os bytes que um segmento traz do arquivo.
    pub fn conteudo(&self, segmento: &Segmento) -> Result<&'a [u8], &'static str> {
        let de = usize::try_from(segmento.no_arquivo).map_err(|_| "deslocamento grande demais")?;
        let ate = de
            .checked_add(
                usize::try_from(segmento.tamanho_no_arquivo)
                    .map_err(|_| "segmento grande demais")?,
            )
            .ok_or("transbordo no conteudo do segmento")?;
        self.bytes.get(de..ate).ok_or("o segmento sai do arquivo")
    }
}

/// Onde a tabela de relocações está, no espaço de endereços do arquivo.
#[derive(Clone, Copy, Debug)]
pub struct Relocacoes {
    pub em: u64,
    pub quantas: usize,
}

/// Lê a seção dinâmica e diz onde estão as relocações.
///
/// # Por que a imagem na memória, e não o arquivo
///
/// Porque é onde as relocações vão ser aplicadas, e porque os endereços que a
/// seção dinâmica carrega são **virtuais**: usá-los contra o arquivo exigiria
/// traduzir cada um para deslocamento de arquivo, procurando em que segmento
/// ele cai. Na imagem copiada o endereço virtual menos a base é o índice, e
/// não há tradução nenhuma a errar.
///
/// `imagem` começa no menor endereço virtual carregado.
pub fn relocacoes(
    imagem: &[u8],
    menor: u64,
    dinamica_em: u64,
    dinamica_bytes: u64,
) -> Result<Relocacoes, &'static str> {
    let inicio = usize::try_from(
        dinamica_em
            .checked_sub(menor)
            .ok_or("a dinamica esta antes da base")?,
    )
    .map_err(|_| "dinamica longe demais")?;
    let bytes = usize::try_from(dinamica_bytes).map_err(|_| "dinamica grande demais")?;
    let secao = imagem
        .get(inicio..inicio.checked_add(bytes).ok_or("transbordo na dinamica")?)
        .ok_or("a secao dinamica sai da imagem")?;

    let (mut rela, mut rela_bytes, mut rela_entrada, mut plt_bytes) = (0u64, 0u64, 0u64, 0u64);

    // A seção é uma lista de pares (etiqueta, valor) terminada por zero.
    for par in secao.as_chunks::<16>().0 {
        let etiqueta = u64_em(par, 0).ok_or("dinamica truncada")?;
        let valor = u64_em(par, 8).ok_or("dinamica truncada")?;
        match etiqueta {
            etiqueta::FIM => break,
            etiqueta::RELA => rela = valor,
            etiqueta::RELA_BYTES => rela_bytes = valor,
            etiqueta::RELA_ENTRADA => rela_entrada = valor,
            etiqueta::BYTES_DA_PLT => plt_bytes = valor,
            _ => {}
        }
    }

    // Uma PLT significa relocações que este carregador não percorre, e
    // ignorá-las daria um kernel que salta para o endereço zero na primeira
    // chamada que passasse por ela. Um kernel `no_std` sem símbolo externo
    // nenhum não tem PLT — e é por isso que a ausência dela é conferida em
    // vez de presumida.
    if plt_bytes != 0 {
        return Err("o kernel tem relocacoes de PLT, que este carregador nao aplica");
    }

    if rela == 0 || rela_bytes == 0 {
        return Ok(Relocacoes { em: 0, quantas: 0 });
    }
    // O tamanho da entrada vem do arquivo e é o passo da tabela, pela mesma
    // razão do `e_phentsize`: um passo menor que o formato faria os campos
    // saírem sobrepostos.
    if rela_entrada != TAMANHO_DA_RELOCACAO as u64 {
        return Err("as relocacoes nao tem o tamanho do formato");
    }
    if !rela_bytes.is_multiple_of(rela_entrada) {
        return Err("a tabela de relocacoes nao e um numero inteiro de entradas");
    }

    Ok(Relocacoes {
        em: rela,
        quantas: (rela_bytes / rela_entrada) as usize,
    })
}
