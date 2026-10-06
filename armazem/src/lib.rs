//! O armazém do Duke, como conta pura.
//!
//! # O que é
//!
//! Uma árvore de arquivos e diretórios, cada nó com uma **versão** — a da
//! última mudança nele — e um **dono**, que paga a cota do que o nó ocupa.
//! O conteúdo dos arquivos não mora aqui, nem na memória do kernel: mora em
//! blocos cifrados de uma partição própria ([`bloco`]), e o que esta conta
//! guarda de cada arquivo é onde ele está ([`Conteudo`]). É só a conta: quem
//! pode mexer, em que caminho, quem tem o arrendamento, e se a mudança está
//! no disco são perguntas de outros lugares (o gate, a coordenação, a
//! persistência), e não chegam aqui. O desenho inteiro está em
//! `docs/ARMAZENAMENTO.md`.
//!
//! # Preparar e aplicar, em lote
//!
//! Uma mutação é um **lote** de operações ([`Op`]), aplicado inteiro ou
//! nada. [`Armazem::preparar`] confere todas, uma depois da outra, cada uma
//! vendo o efeito das anteriores — sem mudar nada —, e devolve o [`Lote`]: o
//! **resultado**, mudança por mudança ([`Mudanca`]). O kernel grava o lote
//! e, **só se a gravação deu certo**, [`Armazem::aplicar`] o põe em vigor.
//! Assim nada vale em memória sem estar no disco, nada de um lote vale sem
//! o resto; e a mesma `aplicar` é a que o boot usa para repor o que o
//! journal diz.
//!
//! # A versão
//!
//! Vem de um contador do armazém inteiro, que só cresce: cada mudança leva
//! o próximo número — um lote, um número por mudança. A versão de um caminho
//! sem nó é 0. Por isso um objeto apagado e criado de novo nunca volta a uma
//! versão já vista — quem guardou a versão 3 do antigo não escreve no novo
//! achando que é o mesmo. Um diretório movido leva versões novas, ele e cada
//! nó abaixo: o que estava em `a/x` agora está em `b/x`, e quem guardou a
//! versão de `a/x` não acha mais nada lá.
//!
//! # Caminhos e diretórios
//!
//! Relativos à raiz do armazém, sem barra no começo nem no fim:
//! `compartilhado/notas.txt`. A raiz é o caminho vazio, e existe sempre. Cada
//! componente tem de 1 a [`MAIOR_COMPONENTE`] bytes de `[A-Za-z0-9._-]`, e
//! não é `.` nem `..`; até [`MAIS_NIVEIS`] componentes.
//!
//! Os diretórios são **explícitos**: nascem por [`Op::CriarDiretorio`],
//! existem vazios, e saem por [`Op::RemoverDiretorio`] — só vazios. Um nó só
//! nasce num diretório que existe: nada cria o pai de passagem, e por isso
//! nada existe num caminho que o gate não decidiu.
//!
//! # A cota
//!
//! Cada nó é de um dono — quem o gravou por último, ou criou o diretório —,
//! e conta para ele: um objeto, e os bytes do conteúdo. Um lote de `ator`
//! que aumentaria o uso dele além da [`Cota`] é recusado inteiro; um que o
//! diminui passa sempre, mesmo acima dela. A conta é feita com o lote
//! inteiro, sobre o estado de agora: o kernel prepara um lote de cada vez,
//! e dois lotes não somam acima da cota por terem sido conferidos ao mesmo
//! tempo.
//!
//! # Os metadados
//!
//! O que a memória do kernel paga por nó — o caminho, o dono, as extensões
//! — é contado ([`Armazem::metadados`]), e o lote que passaria do teto que o
//! kernel dá é recusado. O conteúdo não conta: não está na memória.

#![no_std]

extern crate alloc;

pub mod bloco;
pub mod mapa;
pub mod registro;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// O maior componente de um caminho.
pub const MAIOR_COMPONENTE: usize = 64;
/// Quantos componentes um caminho tem, no máximo.
pub const MAIS_NIVEIS: usize = 8;
/// A maior versão: as versões cabem em 63 bits, para quem as usa como
/// identificador ao lado de outro espaço de números (o VFS do kernel). O
/// contador não chega lá — uma mudança por microssegundo levaria
/// trezentos mil anos —, e se chegasse o armazém diria que está cheio.
pub const MAIOR_VERSAO: u64 = (1 << 63) - 1;
/// O maior nome de dono: `agente:` e uma chave em hex cabem com folga.
pub const MAIOR_DONO: usize = 96;
/// Quantas extensões um arquivo tem, no máximo: o registro de uma mudança
/// leva todas num campo, e o campo cabe em 64 KiB.
pub const MAIS_EXTENSOES: usize = 1024;
/// O que a memória paga por nó, além do caminho, do dono e das extensões.
pub const CUSTO_DE_NO: usize = 64;
/// O que a memória paga por extensão.
pub const CUSTO_DE_EXTENSAO: usize = 40;

/// Quantos bytes de conteúdo um bloco leva — ver [`bloco::CARGA`].
pub const CARGA: u64 = bloco::CARGA as u64;

/// O que um caminho é.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    Arquivo,
    Diretorio,
}

/// Uma faixa de blocos do conteúdo de um arquivo: `quantos` blocos a partir
/// do bloco `bloco` da área de dados, que guardam os blocos lógicos
/// `indice..indice + quantos` do arquivo, cifrados com o `id` da escrita que
/// os fez — ver [`bloco`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Extensao {
    pub bloco: u64,
    pub quantos: u32,
    pub id: [u8; 16],
    pub indice: u64,
}

/// Onde está o conteúdo de um arquivo, e quanto ele tem.
///
/// As extensões cobrem os blocos lógicos `0..blocos()` em ordem, sem
/// buraco e sem sobra: o bloco lógico `k` tem os bytes `k * CARGA ..`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conteudo {
    pub tamanho: u64,
    pub extensoes: Vec<Extensao>,
}

impl Conteudo {
    /// Um arquivo vazio: nenhum bloco.
    pub const fn vazio() -> Conteudo {
        Conteudo {
            tamanho: 0,
            extensoes: Vec::new(),
        }
    }

    /// Quantos blocos o tamanho pede.
    pub fn blocos(&self) -> u64 {
        self.tamanho.div_ceil(CARGA)
    }

    /// As extensões cobrem exatamente os blocos lógicos do tamanho, em
    /// ordem, sem buraco, sem sobra, e sem passar do teto de extensões.
    pub fn valido(&self) -> bool {
        if self.extensoes.len() > MAIS_EXTENSOES {
            return false;
        }
        let mut proximo = 0u64;
        for e in &self.extensoes {
            if e.quantos == 0 || e.indice != proximo {
                return false;
            }
            let Some(p) = proximo.checked_add(u64::from(e.quantos)) else {
                return false;
            };
            if e.bloco.checked_add(u64::from(e.quantos)).is_none() {
                return false;
            }
            proximo = p;
        }
        proximo == self.blocos()
    }

    /// Onde está o bloco lógico `k`: o bloco da área de dados, e o `id` da
    /// escrita que o cifrou.
    pub fn onde(&self, k: u64) -> Option<(u64, [u8; 16])> {
        let i = self
            .extensoes
            .partition_point(|e| e.indice + u64::from(e.quantos) <= k);
        let e = self.extensoes.get(i)?;
        (k >= e.indice).then(|| (e.bloco + (k - e.indice), e.id))
    }

    /// As faixas de blocos da área de dados que o conteúdo ocupa.
    pub fn faixas(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.extensoes
            .iter()
            .map(|e| (e.bloco, e.bloco + u64::from(e.quantos)))
    }
}

/// Um nó da árvore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum No {
    Arquivo {
        versao: u64,
        conteudo: Conteudo,
        dono: String,
    },
    Diretorio {
        versao: u64,
        dono: String,
    },
}

impl No {
    pub fn versao(&self) -> u64 {
        match self {
            No::Arquivo { versao, .. } | No::Diretorio { versao, .. } => *versao,
        }
    }

    pub fn dono(&self) -> &str {
        match self {
            No::Arquivo { dono, .. } | No::Diretorio { dono, .. } => dono,
        }
    }

    pub fn tipo(&self) -> Tipo {
        match self {
            No::Arquivo { .. } => Tipo::Arquivo,
            No::Diretorio { .. } => Tipo::Diretorio,
        }
    }

    /// Os bytes de conteúdo que o nó tem — zero num diretório.
    pub fn tamanho(&self) -> u64 {
        match self {
            No::Arquivo { conteudo, .. } => conteudo.tamanho,
            No::Diretorio { .. } => 0,
        }
    }

    /// O conteúdo, num arquivo.
    pub fn conteudo(&self) -> Option<&Conteudo> {
        match self {
            No::Arquivo { conteudo, .. } => Some(conteudo),
            No::Diretorio { .. } => None,
        }
    }

    fn com_versao(&self, v: u64) -> No {
        let mut n = self.clone();
        match &mut n {
            No::Arquivo { versao, .. } | No::Diretorio { versao, .. } => *versao = v,
        }
        n
    }

    /// O que a memória paga por este nó em `caminho`.
    fn custo(&self, caminho: &str) -> usize {
        let extensoes = self.conteudo().map_or(0, |c| c.extensoes.len());
        CUSTO_DE_NO + caminho.len() + self.dono().len() + CUSTO_DE_EXTENSAO * extensoes
    }
}

/// O que um dono ocupa: objetos e bytes de conteúdo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Uso {
    pub bytes: u64,
    pub objetos: u64,
}

/// O que um dono pode ocupar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cota {
    pub bytes: u64,
    pub objetos: u64,
}

impl Cota {
    /// Cota nenhuma: quem não tem linha na política não ocupa nada.
    pub const NENHUMA: Cota = Cota {
        bytes: 0,
        objetos: 0,
    };
}

/// Uma operação pedida, já decidida pelo gate, a conferir.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// O arquivo passa a ter `conteudo` — cujos blocos o kernel já escreveu
    /// —, contra a versão `esperada`: 0 cria, e recusa se já existe; outra
    /// substitui, e recusa se não é a de agora. Um acréscimo é isto, com o
    /// conteúdo de antes e o que se acrescenta.
    Gravar {
        caminho: String,
        esperada: u64,
        conteudo: Conteudo,
    },
    /// Apaga o arquivo, que tem de estar na versão `esperada`.
    Apagar { caminho: String, esperada: u64 },
    /// Cria o diretório, que não pode existir, num pai que existe.
    CriarDiretorio { caminho: String },
    /// Remove o diretório, vazio, na versão `esperada`.
    RemoverDiretorio { caminho: String, esperada: u64 },
    /// Move o nó em `de` — com tudo abaixo dele, se é diretório —, na
    /// versão `esperada`, para `para`, que não pode existir, num pai que
    /// existe, e não pode estar abaixo de `de`.
    Renomear {
        de: String,
        para: String,
        esperada: u64,
    },
}

impl Op {
    /// Os caminhos que a operação muda — os que o gate tem de ter decidido
    /// e cujo arrendamento conta.
    pub fn caminhos(&self) -> impl Iterator<Item = &str> {
        let (a, b) = match self {
            Op::Gravar { caminho, .. }
            | Op::Apagar { caminho, .. }
            | Op::CriarDiretorio { caminho }
            | Op::RemoverDiretorio { caminho, .. } => (caminho.as_str(), None),
            Op::Renomear { de, para, .. } => (de.as_str(), Some(para.as_str())),
        };
        core::iter::once(a).chain(b)
    }
}

/// Uma mudança, como o journal a guarda e o boot a repõe: o **resultado**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mudanca {
    /// O arquivo em `caminho` passou a ter este conteúdo, nesta versão, de
    /// `dono`.
    Arquivo {
        caminho: String,
        versao: u64,
        conteudo: Conteudo,
        dono: String,
    },
    /// O diretório nasceu.
    Diretorio {
        caminho: String,
        versao: u64,
        dono: String,
    },
    /// O nó — um arquivo, ou um diretório vazio — saiu. A versão é a que a
    /// remoção gastou do contador.
    Removido { caminho: String, versao: u64 },
    /// O nó em `de`, e tudo abaixo dele, foi para `para`. Cada nó movido
    /// leva uma versão nova, a partir de `versao`, na ordem dos caminhos de
    /// origem — o nó de cima primeiro.
    Movido {
        de: String,
        para: String,
        versao: u64,
    },
}

/// Um lote preparado: as mudanças, em ordem, e a versão seguinte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lote {
    pub mudancas: Vec<Mudanca>,
    pub proxima: u64,
}

/// Por que uma conta recusou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O caminho não é um caminho do armazém, ou ficaria fundo demais.
    CaminhoInvalido,
    /// Não há nó nesse caminho.
    NaoExiste,
    /// Já há um nó nesse caminho.
    Existe,
    /// A versão esperada não é a de agora — que vai junto.
    Versao { atual: u64 },
    /// O caminho é um diretório.
    EhDiretorio,
    /// O caminho, ou o pai dele, é um arquivo.
    NaoEhDiretorio,
    /// O pai do caminho não existe.
    PaiNaoExiste,
    /// O diretório tem nós abaixo dele.
    NaoVazio,
    /// O destino de um movimento estaria abaixo da origem.
    DentroDeSi,
    /// O lote passaria da cota de quem pede.
    Cota,
    /// O armazém passaria do teto dele: os metadados, ou as versões.
    Cheio,
    /// Um conteúdo cujas extensões não cobrem o tamanho.
    ConteudoIncoerente,
    /// Uma mudança a aplicar com versão que não é posterior às já vistas —
    /// só o boot a encontra, num journal fora de ordem.
    ForaDeOrdem,
}

impl Recusa {
    /// A recusa, em palavras, para a resposta e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::CaminhoInvalido => "o caminho nao e um caminho do armazem",
            Recusa::NaoExiste => "nao ha nada nesse caminho",
            Recusa::Existe => "ja ha algo nesse caminho",
            Recusa::Versao { .. } => "a versao esperada nao e a de agora",
            Recusa::EhDiretorio => "o caminho e um diretorio",
            Recusa::NaoEhDiretorio => "o caminho, ou o pai dele, e um arquivo",
            Recusa::PaiNaoExiste => "o diretorio pai nao existe",
            Recusa::NaoVazio => "o diretorio nao esta vazio",
            Recusa::DentroDeSi => "o destino estaria abaixo da origem",
            Recusa::Cota => "a cota de quem pede nao comporta",
            Recusa::Cheio => "o armazem passaria do teto dele",
            Recusa::ConteudoIncoerente => "o conteudo nao cobre o tamanho",
            Recusa::ForaDeOrdem => "mudanca com versao fora de ordem",
        }
    }
}

/// Um componente aceitável.
pub fn componente_valido(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= MAIOR_COMPONENTE
        && c != "."
        && c != ".."
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Um caminho de nó aceitável: não vazio, sem barras sobrando, cada
/// componente aceitável, até [`MAIS_NIVEIS`] deles.
pub fn caminho_valido(c: &str) -> bool {
    !c.is_empty() && c.split('/').count() <= MAIS_NIVEIS && c.split('/').all(componente_valido)
}

/// O pai de `c`: `a/b/c` dá `a/b`; `a` dá a raiz, `""`.
pub fn pai(c: &str) -> &str {
    c.rfind('/').map_or("", |i| &c[..i])
}

/// `c` está abaixo de `dir` (e não é ele)?
pub fn abaixo_de(c: &str, dir: &str) -> bool {
    dir.is_empty() || (c.len() > dir.len() && c.starts_with(dir) && c.as_bytes()[dir.len()] == b'/')
}

/// As chaves de um mapa por caminho que estão abaixo de `dir`: a faixa
/// `dir/` até `dir0` — `0` é o byte seguinte a `/`. A raiz é tudo.
fn abaixo<'a, V>(
    m: &'a BTreeMap<String, V>,
    dir: &str,
) -> alloc::collections::btree_map::Range<'a, String, V> {
    if dir.is_empty() {
        return m.range::<String, _>(..);
    }
    let mut de = String::from(dir);
    de.push('/');
    let mut ate = String::from(dir);
    ate.push('0');
    m.range(de..ate)
}

/// Faixas de blocos, `[início, fim)`, em ordem e sem sobreposição.
pub type Faixas = Vec<(u64, u64)>;

/// Ordena e funde faixas.
pub fn normalizar(mut v: Faixas) -> Faixas {
    v.retain(|(a, b)| a < b);
    v.sort_unstable();
    let mut r: Faixas = Vec::with_capacity(v.len());
    for (a, b) in v {
        match r.last_mut() {
            Some((_, fim)) if a <= *fim => *fim = (*fim).max(b),
            _ => r.push((a, b)),
        }
    }
    r
}

/// `a` menos `b`, as duas normalizadas.
pub fn subtrair(a: &[(u64, u64)], b: &[(u64, u64)]) -> Faixas {
    let mut r = Vec::new();
    let mut j = 0;
    for &(mut ini, fim) in a {
        while j < b.len() && b[j].1 <= ini {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && b[k].0 < fim {
            if b[k].0 > ini {
                r.push((ini, b[k].0));
            }
            ini = ini.max(b[k].1);
            k += 1;
        }
        if ini < fim {
            r.push((ini, fim));
        }
    }
    r
}

/// O armazém: os nós, o uso de cada dono, e o contador das versões.
#[derive(Clone, Debug)]
pub struct Armazem {
    nos: BTreeMap<String, No>,
    /// Os caminhos pela versão de agora de cada nó.
    por_versao: BTreeMap<u64, String>,
    uso: BTreeMap<String, Uso>,
    metadados: usize,
    /// A versão da próxima mudança.
    proxima: u64,
}

impl Default for Armazem {
    fn default() -> Self {
        Self::novo()
    }
}

impl PartialEq for Armazem {
    fn eq(&self, outro: &Armazem) -> bool {
        self.nos == outro.nos && self.proxima == outro.proxima
    }
}

impl Armazem {
    /// Um armazém vazio.
    pub const fn novo() -> Armazem {
        Armazem {
            nos: BTreeMap::new(),
            por_versao: BTreeMap::new(),
            uso: BTreeMap::new(),
            metadados: 0,
            proxima: 1,
        }
    }

    /// A versão que a próxima mudança vai levar.
    pub fn proxima(&self) -> u64 {
        self.proxima
    }

    /// Quantos nós há.
    pub fn quantos(&self) -> usize {
        self.nos.len()
    }

    /// O que a memória paga pelos metadados de todos os nós.
    pub fn metadados(&self) -> usize {
        self.metadados
    }

    /// O uso de um dono.
    pub fn uso(&self, dono: &str) -> Uso {
        self.uso.get(dono).copied().unwrap_or_default()
    }

    /// O nó em `c`.
    pub fn no(&self, c: &str) -> Option<&No> {
        self.nos.get(c)
    }

    /// O que `c` é — a raiz, `""`, é sempre um diretório.
    pub fn tipo(&self, c: &str) -> Option<Tipo> {
        if c.is_empty() {
            return Some(Tipo::Diretorio);
        }
        self.nos.get(c).map(No::tipo)
    }

    /// A versão de `c`: a da última mudança, ou 0 se não há nó lá. A raiz
    /// é 0.
    pub fn versao(&self, c: &str) -> u64 {
        self.nos.get(c).map_or(0, No::versao)
    }

    /// O nó cuja versão de agora é `versao`, com o caminho dele. Uma versão
    /// que o nó já deixou para trás não acha nada.
    pub fn por_versao(&self, versao: u64) -> Option<(&str, &No)> {
        let c = self.por_versao.get(&versao)?;
        self.nos.get(c).map(|n| (c.as_str(), n))
    }

    /// Os filhos imediatos do diretório `dir`, em ordem de nome, cada um
    /// com o tipo. Vazio se `dir` não é diretório.
    pub fn filhos(&self, dir: &str) -> Vec<(String, Tipo)> {
        if self.tipo(dir) != Some(Tipo::Diretorio) {
            return Vec::new();
        }
        let corte = if dir.is_empty() { 0 } else { dir.len() + 1 };
        // Na ordem das chaves os filhos imediatos ficam na ordem dos nomes:
        // todos têm o mesmo prefixo, e o que vem depois dele é o nome.
        abaixo(&self.nos, dir)
            .filter(|(c, _)| !c[corte..].contains('/'))
            .map(|(c, n)| (String::from(&c[corte..]), n.tipo()))
            .collect()
    }

    /// Todos os nós, em ordem de caminho — cada diretório antes do que está
    /// abaixo dele. É a ordem da base de uma compactação.
    pub fn todos(&self) -> impl Iterator<Item = (&str, &No)> {
        self.nos.iter().map(|(c, n)| (c.as_str(), n))
    }

    /// As faixas de blocos que os arquivos ocupam, normalizadas: o que o
    /// mapa de blocos tem de marcar depois de repor o armazém.
    pub fn blocos_em_uso(&self) -> Faixas {
        normalizar(
            self.nos
                .values()
                .filter_map(No::conteudo)
                .flat_map(Conteudo::faixas)
                .collect(),
        )
    }

    /// Confere um lote de `ator`, operação por operação, cada uma sobre o
    /// efeito das anteriores, e o prepara — sem mudar nada.
    ///
    /// `cota` é a de `ator`, e `reservado` o que ele já ocupa fora do
    /// armazém (rascunhos ainda não gravados); `teto_de_metadados` é o que
    /// a memória do kernel dá aos metadados. Na recusa, devolve qual
    /// operação recusou — a última, para a cota e o teto, que são do lote.
    pub fn preparar(
        &self,
        ops: &[Op],
        ator: &str,
        cota: Cota,
        reservado: u64,
        teto_de_metadados: usize,
    ) -> Result<Lote, (usize, Recusa)> {
        if ator.is_empty() || ator.len() > MAIOR_DONO {
            return Err((0, Recusa::Cota));
        }
        let mut v = Vista::sobre(self);
        for (i, op) in ops.iter().enumerate() {
            v.operar(op, ator).map_err(|r| (i, r))?;
        }
        let ultimo = ops.len().saturating_sub(1);
        // A cota: só o que o lote **aumenta** se confere.
        let antes = self.uso(ator);
        let (db, dobj) = v.uso.get(ator).copied().unwrap_or((0, 0));
        let depois_bytes = i128::from(antes.bytes) + db;
        let depois_objetos = i128::from(antes.objetos) + dobj;
        if (db > 0 && depois_bytes + i128::from(reservado) > i128::from(cota.bytes))
            || (dobj > 0 && depois_objetos > i128::from(cota.objetos))
        {
            return Err((ultimo, Recusa::Cota));
        }
        if v.metadados > 0 && self.metadados as i128 + v.metadados > teto_de_metadados as i128 {
            return Err((ultimo, Recusa::Cheio));
        }
        Ok(Lote {
            mudancas: v.mudancas,
            proxima: v.proxima,
        })
    }

    /// Põe um lote em vigor: o que acabou de ser gravado, ou o que o boot
    /// leu do journal. Devolve as faixas de blocos que deixaram de ser
    /// usadas — o conteúdo que saiu, e o que nenhum arquivo leva mais.
    ///
    /// Confere de novo o que não depende de quem pediu — o lugar, o tipo, e
    /// que cada versão é posterior às já vistas —, porque o boot não passou
    /// pela preparação. Uma recusa no meio deixa o armazém pela metade: só o
    /// boot a encontra, e um journal que não se reaplica não vale inteiro.
    pub fn aplicar(&mut self, lote: &Lote) -> Result<Faixas, Recusa> {
        let mut saidas: Faixas = Vec::new();
        let mut tocados: Vec<String> = Vec::new();
        for m in &lote.mudancas {
            self.aplicar_uma(m, &mut saidas, &mut tocados)?;
        }
        // A preparação diz a próxima; o boot, que lê só as mudanças, deixa
        // a que elas mesmas deram.
        self.proxima = self.proxima.max(lote.proxima);
        let ficam = normalizar(
            tocados
                .iter()
                .filter_map(|c| self.nos.get(c))
                .filter_map(No::conteudo)
                .flat_map(Conteudo::faixas)
                .collect(),
        );
        Ok(subtrair(&normalizar(saidas), &ficam))
    }

    fn proxima_versao(&self, v: u64) -> Result<(), Recusa> {
        if v < self.proxima {
            return Err(Recusa::ForaDeOrdem);
        }
        if v > MAIOR_VERSAO {
            return Err(Recusa::Cheio);
        }
        Ok(())
    }

    fn conferir_pai(&self, c: &str) -> Result<(), Recusa> {
        match self.tipo(pai(c)) {
            Some(Tipo::Diretorio) => Ok(()),
            Some(Tipo::Arquivo) => Err(Recusa::NaoEhDiretorio),
            None => Err(Recusa::PaiNaoExiste),
        }
    }

    fn aplicar_uma(
        &mut self,
        m: &Mudanca,
        saidas: &mut Faixas,
        tocados: &mut Vec<String>,
    ) -> Result<(), Recusa> {
        match m {
            Mudanca::Arquivo {
                caminho,
                versao,
                conteudo,
                dono,
            } => {
                self.proxima_versao(*versao)?;
                if !caminho_valido(caminho) || dono.is_empty() || dono.len() > MAIOR_DONO {
                    return Err(Recusa::CaminhoInvalido);
                }
                if !conteudo.valido() {
                    return Err(Recusa::ConteudoIncoerente);
                }
                self.conferir_pai(caminho)?;
                match self.nos.get(caminho.as_str()) {
                    Some(No::Diretorio { .. }) => return Err(Recusa::EhDiretorio),
                    Some(No::Arquivo { conteudo, .. }) => saidas.extend(conteudo.faixas()),
                    None => {}
                }
                self.por(
                    caminho,
                    Some(No::Arquivo {
                        versao: *versao,
                        conteudo: conteudo.clone(),
                        dono: dono.clone(),
                    }),
                );
                self.proxima = versao + 1;
                tocados.push(caminho.clone());
            }
            Mudanca::Diretorio {
                caminho,
                versao,
                dono,
            } => {
                self.proxima_versao(*versao)?;
                if !caminho_valido(caminho) || dono.is_empty() || dono.len() > MAIOR_DONO {
                    return Err(Recusa::CaminhoInvalido);
                }
                self.conferir_pai(caminho)?;
                if self.nos.contains_key(caminho.as_str()) {
                    return Err(Recusa::Existe);
                }
                self.por(
                    caminho,
                    Some(No::Diretorio {
                        versao: *versao,
                        dono: dono.clone(),
                    }),
                );
                self.proxima = versao + 1;
            }
            Mudanca::Removido { caminho, versao } => {
                self.proxima_versao(*versao)?;
                match self.nos.get(caminho.as_str()) {
                    None => return Err(Recusa::NaoExiste),
                    Some(No::Arquivo { conteudo, .. }) => saidas.extend(conteudo.faixas()),
                    Some(No::Diretorio { .. }) => {
                        if abaixo(&self.nos, caminho).next().is_some() {
                            return Err(Recusa::NaoVazio);
                        }
                    }
                }
                self.por(caminho, None);
                self.proxima = versao + 1;
            }
            Mudanca::Movido { de, para, versao } => {
                self.proxima_versao(*versao)?;
                if !caminho_valido(de) || !caminho_valido(para) {
                    return Err(Recusa::CaminhoInvalido);
                }
                if de == para || abaixo_de(para, de) {
                    return Err(Recusa::DentroDeSi);
                }
                if !self.nos.contains_key(de.as_str()) {
                    return Err(Recusa::NaoExiste);
                }
                if self.nos.contains_key(para.as_str()) {
                    return Err(Recusa::Existe);
                }
                self.conferir_pai(para)?;
                let sub = self.subarvore(de);
                let mut v = *versao;
                for (c, _) in &sub {
                    if !caminho_valido(&renomeado(c, de, para)) {
                        return Err(Recusa::CaminhoInvalido);
                    }
                }
                for (c, _) in &sub {
                    self.por(c, None);
                }
                for (c, n) in sub {
                    if v > MAIOR_VERSAO {
                        return Err(Recusa::Cheio);
                    }
                    let novo = renomeado(&c, de, para);
                    self.por(&novo, Some(n.com_versao(v)));
                    tocados.push(novo);
                    v += 1;
                }
                self.proxima = v;
            }
        }
        Ok(())
    }

    /// O nó em `raiz` e todos abaixo dele, em ordem de caminho.
    fn subarvore(&self, raiz: &str) -> Vec<(String, No)> {
        let mut v: Vec<(String, No)> = Vec::new();
        if let Some(n) = self.nos.get(raiz) {
            v.push((String::from(raiz), n.clone()));
            v.extend(abaixo(&self.nos, raiz).map(|(c, n)| (c.clone(), n.clone())));
        }
        v
    }

    /// Põe `novo` em `c` (ou tira o que há, com `None`), mantendo o índice
    /// das versões, o uso dos donos e o custo dos metadados.
    fn por(&mut self, c: &str, novo: Option<No>) {
        if let Some(velho) = self.nos.remove(c) {
            self.por_versao.remove(&velho.versao());
            self.metadados -= velho.custo(c);
            let u = self.uso.entry(String::from(velho.dono())).or_default();
            u.bytes -= velho.tamanho();
            u.objetos -= 1;
            if *u == Uso::default() {
                self.uso.remove(velho.dono());
            }
        }
        if let Some(n) = novo {
            self.por_versao.insert(n.versao(), String::from(c));
            self.metadados += n.custo(c);
            let u = self.uso.entry(String::from(n.dono())).or_default();
            u.bytes += n.tamanho();
            u.objetos += 1;
            self.nos.insert(String::from(c), n);
        }
    }

    /// Repõe um nó da base de uma compactação. A base leva os nós em ordem
    /// de caminho — o pai antes —, e cada um com a versão que tinha: as
    /// versões não vêm em ordem, e quem fecha a conta é
    /// [`Armazem::fixar_proxima`], com a próxima que a base diz.
    pub fn restaurar(&mut self, c: &str, no: No) -> Result<(), Recusa> {
        if !caminho_valido(c) || no.dono().is_empty() || no.dono().len() > MAIOR_DONO {
            return Err(Recusa::CaminhoInvalido);
        }
        if no.versao() == 0 || no.versao() > MAIOR_VERSAO {
            return Err(Recusa::ForaDeOrdem);
        }
        if no.conteudo().is_some_and(|c| !c.valido()) {
            return Err(Recusa::ConteudoIncoerente);
        }
        self.conferir_pai(c)?;
        if self.nos.contains_key(c) {
            return Err(Recusa::Existe);
        }
        if self.por_versao.contains_key(&no.versao()) {
            return Err(Recusa::ForaDeOrdem);
        }
        self.por(c, Some(no));
        Ok(())
    }

    /// Repõe a próxima versão, da base: tem de passar de todas as versões
    /// repostas, e só cresce.
    pub fn fixar_proxima(&mut self, n: u64) -> Result<(), Recusa> {
        let maior = self.por_versao.keys().next_back().copied().unwrap_or(0);
        if n <= maior || n < self.proxima || n > MAIOR_VERSAO + 1 {
            return Err(Recusa::ForaDeOrdem);
        }
        self.proxima = n;
        Ok(())
    }

    /// Para os testes e para o boot: as contas de dentro conferem com os
    /// nós — cada versão aponta para o nó que a tem, o uso de cada dono e o
    /// custo dos metadados somam o que os nós dizem, todo nó tem o pai
    /// diretório, e nenhuma versão passa da próxima.
    pub fn coerente(&self) -> bool {
        let versoes = self.por_versao.len() == self.nos.len()
            && self.nos.iter().all(|(c, n)| {
                self.por_versao.get(&n.versao()) == Some(c) && n.versao() < self.proxima
            });
        let mut uso: BTreeMap<&str, Uso> = BTreeMap::new();
        let mut metadados = 0usize;
        for (c, n) in &self.nos {
            let u = uso.entry(n.dono()).or_default();
            u.bytes += n.tamanho();
            u.objetos += 1;
            metadados += n.custo(c);
        }
        let usos =
            uso.len() == self.uso.len() && uso.iter().all(|(d, u)| self.uso.get(*d) == Some(u));
        let pais = self
            .nos
            .keys()
            .all(|c| self.tipo(pai(c)) == Some(Tipo::Diretorio));
        let conteudos = self
            .nos
            .values()
            .filter_map(No::conteudo)
            .all(Conteudo::valido);
        // Nenhum bloco é de dois arquivos.
        let mut faixas: Faixas = self
            .nos
            .values()
            .filter_map(No::conteudo)
            .flat_map(Conteudo::faixas)
            .collect();
        faixas.sort_unstable();
        let disjuntas = faixas.windows(2).all(|w| w[0].1 <= w[1].0);
        versoes && usos && metadados == self.metadados && pais && conteudos && disjuntas
    }
}

/// `c`, que está em `de` ou abaixo dele, levado para `para`.
fn renomeado(c: &str, de: &str, para: &str) -> String {
    let mut s = String::from(para);
    s.push_str(&c[de.len()..]);
    s
}

/// O armazém visto através das mudanças de um lote ainda não aplicado.
struct Vista<'a> {
    base: &'a Armazem,
    mudado: BTreeMap<String, Option<No>>,
    proxima: u64,
    /// O que o lote soma ao uso de cada dono: bytes e objetos.
    uso: BTreeMap<String, (i128, i128)>,
    /// O que o lote soma ao custo dos metadados.
    metadados: i128,
    mudancas: Vec<Mudanca>,
}

impl<'a> Vista<'a> {
    fn sobre(base: &'a Armazem) -> Vista<'a> {
        Vista {
            base,
            mudado: BTreeMap::new(),
            proxima: base.proxima,
            uso: BTreeMap::new(),
            metadados: 0,
            mudancas: Vec::new(),
        }
    }

    fn no(&self, c: &str) -> Option<&No> {
        match self.mudado.get(c) {
            Some(n) => n.as_ref(),
            None => self.base.nos.get(c),
        }
    }

    fn tipo(&self, c: &str) -> Option<Tipo> {
        if c.is_empty() {
            return Some(Tipo::Diretorio);
        }
        self.no(c).map(No::tipo)
    }

    fn conferir_pai(&self, c: &str) -> Result<(), Recusa> {
        match self.tipo(pai(c)) {
            Some(Tipo::Diretorio) => Ok(()),
            Some(Tipo::Arquivo) => Err(Recusa::NaoEhDiretorio),
            None => Err(Recusa::PaiNaoExiste),
        }
    }

    /// O nó em `raiz` e todos os que existem abaixo dele, na vista, em
    /// ordem de caminho.
    fn subarvore(&self, raiz: &str) -> Vec<(String, No)> {
        let mut todos: BTreeMap<String, No> = BTreeMap::new();
        for (c, n) in abaixo(&self.base.nos, raiz) {
            if !self.mudado.contains_key(c) {
                todos.insert(c.clone(), n.clone());
            }
        }
        for (c, n) in abaixo(&self.mudado, raiz) {
            if let Some(n) = n {
                todos.insert(c.clone(), n.clone());
            }
        }
        let mut v: Vec<(String, No)> = Vec::new();
        if let Some(n) = self.no(raiz) {
            v.push((String::from(raiz), n.clone()));
        }
        v.extend(todos);
        v
    }

    fn tem_filhos(&self, dir: &str) -> bool {
        abaixo(&self.base.nos, dir).any(|(c, _)| !self.mudado.contains_key(c))
            || abaixo(&self.mudado, dir).any(|(_, n)| n.is_some())
    }

    fn versao_nova(&mut self) -> Result<u64, Recusa> {
        let v = self.proxima;
        if v > MAIOR_VERSAO {
            return Err(Recusa::Cheio);
        }
        self.proxima += 1;
        Ok(v)
    }

    fn por(&mut self, c: &str, novo: Option<No>) {
        if let Some(velho) = self.no(c).cloned() {
            let d = self.uso.entry(String::from(velho.dono())).or_default();
            d.0 -= i128::from(velho.tamanho());
            d.1 -= 1;
            self.metadados -= velho.custo(c) as i128;
        }
        if let Some(n) = &novo {
            let d = self.uso.entry(String::from(n.dono())).or_default();
            d.0 += i128::from(n.tamanho());
            d.1 += 1;
            self.metadados += n.custo(c) as i128;
        }
        self.mudado.insert(String::from(c), novo);
    }

    fn operar(&mut self, op: &Op, ator: &str) -> Result<(), Recusa> {
        for c in op.caminhos() {
            if !caminho_valido(c) {
                return Err(Recusa::CaminhoInvalido);
            }
        }
        match op {
            Op::Gravar {
                caminho,
                esperada,
                conteudo,
            } => {
                if !conteudo.valido() {
                    return Err(Recusa::ConteudoIncoerente);
                }
                self.conferir_pai(caminho)?;
                let atual = match self.no(caminho) {
                    Some(No::Diretorio { .. }) => return Err(Recusa::EhDiretorio),
                    Some(n) => n.versao(),
                    None => 0,
                };
                if *esperada != atual {
                    return Err(Recusa::Versao { atual });
                }
                let versao = self.versao_nova()?;
                self.por(
                    caminho,
                    Some(No::Arquivo {
                        versao,
                        conteudo: conteudo.clone(),
                        dono: String::from(ator),
                    }),
                );
                self.mudancas.push(Mudanca::Arquivo {
                    caminho: caminho.clone(),
                    versao,
                    conteudo: conteudo.clone(),
                    dono: String::from(ator),
                });
            }
            Op::Apagar { caminho, esperada } => {
                let atual = match self.no(caminho) {
                    None => return Err(Recusa::NaoExiste),
                    Some(No::Diretorio { .. }) => return Err(Recusa::EhDiretorio),
                    Some(n) => n.versao(),
                };
                if *esperada != atual {
                    return Err(Recusa::Versao { atual });
                }
                let versao = self.versao_nova()?;
                self.por(caminho, None);
                self.mudancas.push(Mudanca::Removido {
                    caminho: caminho.clone(),
                    versao,
                });
            }
            Op::CriarDiretorio { caminho } => {
                self.conferir_pai(caminho)?;
                if self.no(caminho).is_some() {
                    return Err(Recusa::Existe);
                }
                let versao = self.versao_nova()?;
                self.por(
                    caminho,
                    Some(No::Diretorio {
                        versao,
                        dono: String::from(ator),
                    }),
                );
                self.mudancas.push(Mudanca::Diretorio {
                    caminho: caminho.clone(),
                    versao,
                    dono: String::from(ator),
                });
            }
            Op::RemoverDiretorio { caminho, esperada } => {
                let atual = match self.no(caminho) {
                    None => return Err(Recusa::NaoExiste),
                    Some(No::Arquivo { .. }) => return Err(Recusa::NaoEhDiretorio),
                    Some(n) => n.versao(),
                };
                if *esperada != atual {
                    return Err(Recusa::Versao { atual });
                }
                if self.tem_filhos(caminho) {
                    return Err(Recusa::NaoVazio);
                }
                let versao = self.versao_nova()?;
                self.por(caminho, None);
                self.mudancas.push(Mudanca::Removido {
                    caminho: caminho.clone(),
                    versao,
                });
            }
            Op::Renomear { de, para, esperada } => {
                let atual = self.no(de).map(No::versao).ok_or(Recusa::NaoExiste)?;
                if *esperada != atual {
                    return Err(Recusa::Versao { atual });
                }
                if de == para || abaixo_de(para, de) {
                    return Err(Recusa::DentroDeSi);
                }
                if self.no(para).is_some() {
                    return Err(Recusa::Existe);
                }
                self.conferir_pai(para)?;
                let sub = self.subarvore(de);
                for (c, _) in &sub {
                    if !caminho_valido(&renomeado(c, de, para)) {
                        return Err(Recusa::CaminhoInvalido);
                    }
                }
                let primeira = self.proxima;
                for (c, _) in &sub {
                    self.por(c, None);
                }
                for (c, n) in sub {
                    let v = self.versao_nova()?;
                    self.por(&renomeado(&c, de, para), Some(n.com_versao(v)));
                }
                self.mudancas.push(Mudanca::Movido {
                    de: de.clone(),
                    para: para.clone(),
                    versao: primeira,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod testes;
