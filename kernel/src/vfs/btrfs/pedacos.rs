//! A tradução de endereço lógico para deslocamento no disco.
//!
//! # A circularidade, e como o formato a quebra
//!
//! Todo endereço que o Btrfs guarda é **lógico**: um número num espaço que
//! não é o do disco. O que traduz um no outro é a árvore de pedaços — e ela
//! própria é descrita por um endereço lógico, no superbloco. Para lê-la é
//! preciso traduzir; para traduzir é preciso lê-la.
//!
//! O formato quebra isso carregando, dentro do superbloco, um vetor com os
//! pedaços mínimos para alcançar a árvore. São 129 bytes nesta imagem: uma
//! chave e um pedaço de sistema que cobre o endereço onde a árvore mora.
//! Depois dela lida, o mapa pode crescer com o resto — e o que está aqui é
//! suficiente para o primeiro passo.
//!
//! # Por que só a primeira faixa
//!
//! Porque os perfis que este leitor aceita guardam **cópias inteiras** em
//! cada faixa: um pedaço `single` tem uma, e um `DUP` ou `RAID1` tem duas
//! iguais. Ler a primeira é ler o conteúdo.
//!
//! Isso deixa de valer no instante em que o pedaço for `RAID0`, `RAID10` ou
//! paridade, onde cada faixa tem um pedaço **diferente** do dado e montar o
//! bloco exige intercalar. Esses são recusados por nome, e não ignorados: um
//! leitor que os tratasse como `single` devolveria um bloco com um sexto do
//! conteúdo certo e o resto de outro lugar, e a soma de verificação acusaria
//! sem dizer por quê.

/// Quantos pedaços este mapa guarda.
///
/// Oito. O vetor do superbloco tem um nesta imagem, e a árvore de pedaços
/// deste sistema de arquivos tem três. O número existe para que um mapa
/// absurdo vire um teto em vez de crescer com o que o disco disser.
pub const MAX: usize = 8;

/// Os bits de perfil que este leitor **não** sabe montar.
///
/// `RAID0` (0x8), `RAID10` (0x40), `RAID5` (0x80) e `RAID6` (0x100). Os
/// demais bits de perfil — `RAID1` (0x10), `DUP` (0x20) e os `RAID1C*` — são
/// espelhos, e para eles a primeira faixa basta.
const PERFIS_NAO_SUPORTADOS: u64 = 0x8 | 0x40 | 0x80 | 0x100;

/// Deslocamentos dentro de uma chave do disco.
const CHAVE_TAMANHO: usize = 17;
const CHAVE_TIPO: usize = 8;
const CHAVE_OFFSET: usize = 9;

/// O tipo de chave de um item de pedaço.
const CHUNK_ITEM: u8 = 228;

/// Deslocamentos dentro de um item de pedaço.
mod item {
    pub const TAMANHO_DO_PEDACO: usize = 0;
    pub const TIPO: usize = 24;
    pub const FAIXAS: usize = 44;
    /// Onde começa o vetor de faixas, e quanto cada uma ocupa.
    pub const PRIMEIRA_FAIXA: usize = 48;
    pub const POR_FAIXA: usize = 32;
    /// Dentro de uma faixa: o deslocamento no dispositivo.
    pub const FAIXA_OFFSET: usize = 8;
}

/// Um pedaço: uma faixa contígua do espaço lógico e onde ela mora no disco.
#[derive(Clone, Copy, Debug)]
pub struct Pedaco {
    pub logico: u64,
    pub tamanho: u64,
    /// O deslocamento da primeira faixa, no dispositivo.
    pub fisico: u64,
    pub tipo: u64,
    pub faixas: u16,
}

/// Os pedaços conhecidos, e a tradução que eles permitem.
pub struct Mapa {
    pedacos: [Option<Pedaco>; MAX],
}

impl Mapa {
    pub fn vazio() -> Mapa {
        Mapa {
            pedacos: [None; MAX],
        }
    }

    pub fn acrescentar(&mut self, pedaco: Pedaco) -> Result<(), &'static str> {
        let vaga = self
            .pedacos
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or("mais pedacos do que o mapa comporta")?;
        *vaga = Some(pedaco);
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Pedaco> {
        self.pedacos.iter().flatten()
    }

    pub fn quantos(&self) -> usize {
        self.iter().count()
    }

    /// Onde, no disco, mora o endereço lógico pedido.
    ///
    /// # Uma advertência sobre testar isto
    ///
    /// Na imagem que o `xtask` monta, o deslocamento da primeira faixa de
    /// cada pedaço é **igual** ao endereço lógico dele. Não é regra do
    /// formato; é como o `mkfs.btrfs` acabou dispondo um disco recém-criado.
    /// O efeito é que uma tradução que devolvesse o endereço sem traduzir
    /// funcionaria em tudo que este kernel lê hoje.
    ///
    /// Por isso a aritmética mora numa função sem estado, que a suíte
    /// exercita com pedaços montados à mão em endereços que **não**
    /// coincidem. Testá-la só contra o disco seria não testá-la.
    pub fn traduzir(&self, logico: u64) -> Option<u64> {
        let pedaco = self
            .iter()
            .find(|p| logico >= p.logico && logico - p.logico < p.tamanho)?;
        pedaco.fisico.checked_add(logico - pedaco.logico)
    }
}

/// Interpreta um item de pedaço, dado o endereço lógico que a chave trouxe.
///
/// Devolve também quantos bytes o item ocupou, porque o tamanho depende do
/// número de faixas e quem percorre um vetor de itens precisa saber onde o
/// seguinte começa.
pub fn ler_item(logico: u64, bytes: &[u8]) -> Result<(Pedaco, usize), &'static str> {
    let ler_u64 = |em: usize| -> Option<u64> {
        let fatia = bytes.get(em..em + 8)?;
        Some(u64::from_le_bytes(fatia.try_into().ok()?))
    };

    let tamanho = ler_u64(item::TAMANHO_DO_PEDACO).ok_or("item de pedaco truncado")?;
    let tipo = ler_u64(item::TIPO).ok_or("item de pedaco truncado")?;
    let faixas = {
        let fatia = bytes
            .get(item::FAIXAS..item::FAIXAS + 2)
            .ok_or("item de pedaco truncado")?;
        u16::from_le_bytes([fatia[0], fatia[1]])
    };

    if faixas == 0 {
        return Err("pedaco sem faixa nenhuma");
    }
    if tipo & PERFIS_NAO_SUPORTADOS != 0 {
        return Err("perfil de pedaco que este leitor nao sabe montar");
    }
    // Um pedaço de tamanho zero cobriria um intervalo vazio e faria a busca
    // nunca casar — mas um de tamanho absurdo casaria com tudo.
    if tamanho == 0 {
        return Err("pedaco de tamanho zero");
    }

    let fisico = ler_u64(item::PRIMEIRA_FAIXA + item::FAIXA_OFFSET).ok_or("faixa truncada")?;
    let ocupado = item::PRIMEIRA_FAIXA + faixas as usize * item::POR_FAIXA;
    if bytes.len() < ocupado {
        return Err("o item nao traz todas as faixas que anuncia");
    }

    Ok((
        Pedaco {
            logico,
            tamanho,
            fisico,
            tipo,
            faixas,
        },
        ocupado,
    ))
}

/// Monta o mapa a partir do vetor que o superbloco carrega.
///
/// O vetor é uma sequência de pares chave-item, sem cabeçalho nem contagem:
/// o que diz onde um acaba é o número de faixas do anterior.
pub fn do_vetor_do_sistema(vetor: &[u8]) -> Result<Mapa, &'static str> {
    let mut mapa = Mapa::vazio();
    let mut em = 0usize;

    while em + CHAVE_TAMANHO <= vetor.len() {
        let chave = &vetor[em..em + CHAVE_TAMANHO];
        if chave[CHAVE_TIPO] != CHUNK_ITEM {
            return Err("o vetor do sistema traz algo que nao e um pedaco");
        }
        let logico = u64::from_le_bytes(
            chave[CHAVE_OFFSET..CHAVE_OFFSET + 8]
                .try_into()
                .map_err(|_| "chave truncada")?,
        );

        let (pedaco, ocupado) = ler_item(logico, &vetor[em + CHAVE_TAMANHO..])?;
        mapa.acrescentar(pedaco)?;
        em += CHAVE_TAMANHO + ocupado;
    }

    if mapa.quantos() == 0 {
        return Err("o vetor do sistema nao traz pedaco nenhum");
    }
    Ok(mapa)
}
