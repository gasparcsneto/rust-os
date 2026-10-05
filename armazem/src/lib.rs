//! O armazém do Duke, como conta pura.
//!
//! # O que é
//!
//! Uma árvore de arquivos de texto, cada um com uma **versão** — a da última
//! mudança nele —, sob tetos que não deixam o armazém tomar o lugar do
//! estado de autoridade no journal. É só a conta: quem pode mexer, em que
//! caminho, quem tem o arrendamento, e se a mudança está no disco são
//! perguntas de outros lugares (o gate, a coordenação, a persistência), e
//! não chegam aqui. O desenho inteiro está em `docs/ARMAZENAMENTO.md`.
//!
//! # Preparar e aplicar
//!
//! Uma mutação é feita em dois passos. [`Armazem::preparar_gravacao`] (e as
//! irmãs) confere tudo e devolve a [`Mudanca`] — sem mudar nada. O kernel
//! grava a mudança no journal e, **só se a gravação deu certo**,
//! [`Armazem::aplicar`] a põe em vigor. Assim uma mudança nunca vale em
//! memória sem estar no disco; e a mesma `aplicar` é a que o boot usa para
//! repor o que o journal diz.
//!
//! # A versão
//!
//! Vem de um contador do armazém inteiro, que só cresce: cada mutação leva
//! o próximo número. A versão de um objeto que não existe é 0. Por isso um
//! objeto apagado e criado de novo nunca volta a uma versão já vista — quem
//! guardou a versão 3 do antigo não escreve no novo achando que é o mesmo.
//!
//! # Caminhos
//!
//! Relativos à raiz do armazém, sem barra no começo nem no fim:
//! `compartilhado/notas.txt`. A raiz é o caminho vazio. Cada componente tem
//! de 1 a [`MAIOR_COMPONENTE`] bytes de `[A-Za-z0-9._-]`, e não é `.` nem
//! `..`; até [`MAIS_NIVEIS`] componentes. Os diretórios são implícitos:
//! existem enquanto há arquivo abaixo deles.
//!
//! # Como quem lê reencontra um objeto
//!
//! Pela versão. Ela é única no armazém inteiro e nomeia exatamente um
//! conteúdo de um arquivo — o resultado da mudança daquele número —, então
//! quem guardou a versão de um arquivo para lê-lo aos pedaços nunca recebe
//! um pedaço de um conteúdo e o seguinte de outro: depois de uma mudança, a
//! versão guardada não acha mais nada ([`Armazem::por_versao`]). Os
//! diretórios têm um número próprio, estável enquanto o diretório existe
//! ([`Armazem::id_do_diretorio`]).

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// O maior arquivo, em bytes.
pub const MAIOR_ARQUIVO: usize = 16 * 1024;
/// Quantos arquivos o armazém guarda, no máximo.
pub const MAIS_ARQUIVOS: usize = 256;
/// Quanto o armazém inteiro guarda, em bytes de conteúdo.
///
/// O armazém mora no heap do kernel, que tem 4 MiB e é de todos: um
/// armazém cheio não pode deixar sem memória uma operação de segurança.
/// Um oitavo do heap.
pub const MAIOR_ARMAZEM: usize = 512 * 1024;
/// O maior componente de um caminho.
pub const MAIOR_COMPONENTE: usize = 64;
/// Quantos componentes um caminho tem, no máximo.
pub const MAIS_NIVEIS: usize = 8;
/// A maior versão: as versões cabem em 63 bits, para quem as usa como
/// identificador ao lado de outro espaço de números (o VFS do kernel). O
/// contador não chega lá — uma mudança por microssegundo levaria
/// trezentos mil anos —, e se chegasse o armazém diria que está cheio.
pub const MAIOR_VERSAO: u64 = (1 << 63) - 1;

/// O que um caminho é.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    Arquivo,
    Diretorio,
}

/// Um arquivo.
#[derive(Debug)]
pub struct Objeto {
    versao: u64,
    dados: Vec<u8>,
}

impl Objeto {
    /// A versão da última mudança.
    pub fn versao(&self) -> u64 {
        self.versao
    }

    /// O conteúdo.
    pub fn dados(&self) -> &[u8] {
        &self.dados
    }
}

impl Drop for Objeto {
    fn drop(&mut self) {
        zerar(&mut self.dados);
    }
}

/// Zera os bytes antes de devolvê-los ao alocador: o conteúdo de um
/// arquivo pode ser de alguém, e o heap reaproveita a memória.
fn zerar(v: &mut [u8]) {
    for b in v.iter_mut() {
        // SAFETY: o byte é desta fatia, vivo e alinhado.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Uma mudança preparada, a gravar e a aplicar.
///
/// É o **resultado** da operação, e não o pedido: o conteúdo inteiro que o
/// arquivo passa a ter, com a versão que ele passa a ter. O boot a aplica
/// sem precisar saber o que havia antes nem o que foi pedido.
#[derive(Debug, PartialEq, Eq)]
pub enum Mudanca {
    Gravado {
        caminho: String,
        versao: u64,
        dados: Vec<u8>,
    },
    Apagado {
        caminho: String,
        versao: u64,
    },
}

impl Mudanca {
    /// O caminho que ela muda.
    pub fn caminho(&self) -> &str {
        match self {
            Mudanca::Gravado { caminho, .. } | Mudanca::Apagado { caminho, .. } => caminho,
        }
    }

    /// A versão que ela leva.
    pub fn versao(&self) -> u64 {
        match self {
            Mudanca::Gravado { versao, .. } | Mudanca::Apagado { versao, .. } => *versao,
        }
    }
}

impl Drop for Mudanca {
    fn drop(&mut self) {
        if let Mudanca::Gravado { dados, .. } = self {
            zerar(dados);
        }
    }
}

/// Por que uma conta recusou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O caminho não é um caminho do armazém.
    CaminhoInvalido,
    /// Não há arquivo nesse caminho.
    NaoExiste,
    /// A versão esperada não é a de agora — que vai junto.
    Versao { atual: u64 },
    /// O caminho é um diretório: há arquivos abaixo dele.
    EhDiretorio,
    /// Um componente do meio do caminho é um arquivo.
    PaiEhArquivo,
    /// O arquivo passaria do teto de um arquivo.
    Grande,
    /// O armazém passaria de um teto dele: arquivos ou bytes.
    Cheio,
    /// Uma mudança a aplicar com versão que não é posterior às já vistas —
    /// só o boot a encontra, num journal fora de ordem.
    ForaDeOrdem,
}

impl Recusa {
    /// A recusa, em palavras, para a resposta e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::CaminhoInvalido => "o caminho nao e um caminho do armazem",
            Recusa::NaoExiste => "nao ha arquivo nesse caminho",
            Recusa::Versao { .. } => "a versao esperada nao e a de agora",
            Recusa::EhDiretorio => "o caminho e um diretorio",
            Recusa::PaiEhArquivo => "um componente do caminho e um arquivo",
            Recusa::Grande => "o arquivo passaria do teto de um arquivo",
            Recusa::Cheio => "o armazem passaria do teto dele",
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

/// Um caminho de arquivo aceitável: não vazio, sem barras sobrando, cada
/// componente aceitável, até [`MAIS_NIVEIS`] deles.
pub fn caminho_valido(c: &str) -> bool {
    !c.is_empty() && c.split('/').count() <= MAIS_NIVEIS && c.split('/').all(componente_valido)
}

/// Um diretório que existe: o número dele, e quantos arquivos há abaixo.
#[derive(Debug)]
struct Diretorio {
    id: u64,
    arquivos: usize,
}

/// O armazém.
#[derive(Debug)]
pub struct Armazem {
    objetos: BTreeMap<String, Objeto>,
    /// Os caminhos pela versão de agora de cada arquivo.
    por_versao: BTreeMap<u64, String>,
    /// Os diretórios que existem — os que têm arquivo abaixo —, menos a
    /// raiz, que existe sempre e é o número 0.
    diretorios: BTreeMap<String, Diretorio>,
    /// Os diretórios pelo número.
    por_diretorio: BTreeMap<u64, String>,
    /// A versão da próxima mudança.
    proxima: u64,
    /// O número do próximo diretório: nunca reaproveitado em memória. Não
    /// vai para o disco.
    proximo_diretorio: u64,
    /// Os bytes de conteúdo guardados.
    bytes: usize,
}

impl Default for Armazem {
    fn default() -> Self {
        Self::novo()
    }
}

impl Armazem {
    /// Um armazém vazio.
    pub const fn novo() -> Armazem {
        Armazem {
            objetos: BTreeMap::new(),
            por_versao: BTreeMap::new(),
            diretorios: BTreeMap::new(),
            por_diretorio: BTreeMap::new(),
            proxima: 1,
            proximo_diretorio: 1,
            bytes: 0,
        }
    }

    /// A versão que a próxima mudança vai levar.
    pub fn proxima(&self) -> u64 {
        self.proxima
    }

    /// Repõe a próxima versão, da base de uma compactação. Só cresce.
    pub fn fixar_proxima(&mut self, n: u64) {
        self.proxima = self.proxima.max(n);
    }

    /// Quantos arquivos, e quantos bytes de conteúdo.
    pub fn ocupacao(&self) -> (usize, usize) {
        (self.objetos.len(), self.bytes)
    }

    /// O que `c` é — a raiz, `""`, é sempre um diretório.
    pub fn tipo(&self, c: &str) -> Option<Tipo> {
        if c.is_empty() {
            return Some(Tipo::Diretorio);
        }
        if self.objetos.contains_key(c) {
            return Some(Tipo::Arquivo);
        }
        self.diretorios.contains_key(c).then_some(Tipo::Diretorio)
    }

    /// O número do diretório `c` — 0 para a raiz, `""` —, enquanto ele
    /// existe.
    pub fn id_do_diretorio(&self, c: &str) -> Option<u64> {
        if c.is_empty() {
            return Some(0);
        }
        self.diretorios.get(c).map(|d| d.id)
    }

    /// O diretório de número `id`, se ele ainda existe.
    pub fn diretorio(&self, id: u64) -> Option<&str> {
        if id == 0 {
            return Some("");
        }
        self.por_diretorio.get(&id).map(String::as_str)
    }

    /// Os diretórios acima do arquivo `c`, do mais alto ao mais baixo:
    /// `a/b/c` dá `a` e `a/b`.
    fn acima(c: &str) -> impl Iterator<Item = &str> {
        c.match_indices('/').map(move |(i, _)| &c[..i])
    }

    /// A versão de `c`: a da última mudança, ou 0 se não há arquivo lá.
    pub fn versao(&self, c: &str) -> u64 {
        self.objetos.get(c).map_or(0, |o| o.versao)
    }

    /// O arquivo em `c`.
    pub fn objeto(&self, c: &str) -> Option<&Objeto> {
        self.objetos.get(c)
    }

    /// O arquivo cuja versão de agora é `versao`, com o caminho dele. Uma
    /// versão que o arquivo já deixou para trás não acha nada.
    pub fn por_versao(&self, versao: u64) -> Option<(&str, &Objeto)> {
        let c = self.por_versao.get(&versao)?;
        self.objetos.get(c).map(|o| (c.as_str(), o))
    }

    /// Os filhos imediatos do diretório `dir`, em ordem de nome, cada um
    /// com o tipo. Vazio se `dir` não é diretório.
    pub fn filhos(&self, dir: &str) -> Vec<(String, Tipo)> {
        let mut prefixo = String::from(dir);
        if !dir.is_empty() {
            prefixo.push('/');
        }
        let mut v: Vec<(String, Tipo)> = Vec::new();
        for (k, _) in self.objetos.range(prefixo.clone()..) {
            let Some(resto) = k.strip_prefix(prefixo.as_str()) else {
                break;
            };
            let (nome, tipo) = match resto.split_once('/') {
                Some((nome, _)) => (nome, Tipo::Diretorio),
                None => (resto, Tipo::Arquivo),
            };
            // Os caminhos abaixo de um mesmo diretório são vizinhos na
            // ordem das chaves: basta olhar o último.
            if v.last().is_none_or(|(n, _)| n != nome) {
                v.push((String::from(nome), tipo));
            }
        }
        // A ordem das chaves não é a dos nomes: `b-c` vem antes de `b/x`.
        v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Todos os arquivos, em ordem de caminho — para a base de uma
    /// compactação.
    pub fn todos(&self) -> impl Iterator<Item = (&str, &Objeto)> {
        self.objetos.iter().map(|(c, o)| (c.as_str(), o))
    }

    /// Confere que `c` pode ser um arquivo: caminho válido, não é um
    /// diretório, e nenhum componente do meio é um arquivo.
    fn conferir_lugar(&self, c: &str) -> Result<(), Recusa> {
        if !caminho_valido(c) {
            return Err(Recusa::CaminhoInvalido);
        }
        if self.diretorios.contains_key(c) {
            return Err(Recusa::EhDiretorio);
        }
        if Self::acima(c).any(|d| self.objetos.contains_key(d)) {
            return Err(Recusa::PaiEhArquivo);
        }
        Ok(())
    }

    /// Confere os tetos para `c` passar a ter `novos` bytes.
    fn conferir_tetos(&self, c: &str, novos: usize) -> Result<(), Recusa> {
        if novos > MAIOR_ARQUIVO {
            return Err(Recusa::Grande);
        }
        let antigos = self.objetos.get(c).map_or(0, |o| o.dados.len());
        let quantos = self.objetos.len() + usize::from(!self.objetos.contains_key(c));
        if quantos > MAIS_ARQUIVOS
            || self.bytes - antigos + novos > MAIOR_ARMAZEM
            || self.proxima > MAIOR_VERSAO
        {
            return Err(Recusa::Cheio);
        }
        Ok(())
    }

    /// Prepara a gravação de `dados` em `c`, contra a versão `esperada`:
    /// 0 cria — e recusa se já existe —; outra substitui — e recusa se não
    /// é a de agora.
    pub fn preparar_gravacao(
        &self,
        c: &str,
        esperada: u64,
        dados: &[u8],
    ) -> Result<Mudanca, Recusa> {
        self.conferir_lugar(c)?;
        let atual = self.versao(c);
        if esperada != atual {
            return Err(Recusa::Versao { atual });
        }
        self.conferir_tetos(c, dados.len())?;
        Ok(Mudanca::Gravado {
            caminho: String::from(c),
            versao: self.proxima,
            dados: dados.to_vec(),
        })
    }

    /// Prepara o acréscimo de `mais` ao fim do arquivo `c`, que tem de
    /// existir e estar na versão `esperada`.
    pub fn preparar_acrescimo(
        &self,
        c: &str,
        esperada: u64,
        mais: &[u8],
    ) -> Result<Mudanca, Recusa> {
        self.conferir_lugar(c)?;
        let o = self.objetos.get(c).ok_or(Recusa::NaoExiste)?;
        if esperada != o.versao {
            return Err(Recusa::Versao { atual: o.versao });
        }
        let total = o
            .dados
            .len()
            .checked_add(mais.len())
            .ok_or(Recusa::Grande)?;
        self.conferir_tetos(c, total)?;
        let mut dados = Vec::with_capacity(total);
        dados.extend_from_slice(&o.dados);
        dados.extend_from_slice(mais);
        Ok(Mudanca::Gravado {
            caminho: String::from(c),
            versao: self.proxima,
            dados,
        })
    }

    /// Prepara a remoção do arquivo `c`, que tem de existir e estar na
    /// versão `esperada`.
    pub fn preparar_remocao(&self, c: &str, esperada: u64) -> Result<Mudanca, Recusa> {
        if !caminho_valido(c) {
            return Err(Recusa::CaminhoInvalido);
        }
        if self.proxima > MAIOR_VERSAO {
            return Err(Recusa::Cheio);
        }
        let o = self.objetos.get(c).ok_or(Recusa::NaoExiste)?;
        if esperada != o.versao {
            return Err(Recusa::Versao { atual: o.versao });
        }
        Ok(Mudanca::Apagado {
            caminho: String::from(c),
            versao: self.proxima,
        })
    }

    /// Põe uma mudança em vigor: a que acabou de ser gravada, ou a que o
    /// boot leu do journal.
    ///
    /// Confere de novo o que não depende de quem pediu — o lugar, os tetos,
    /// e que a versão é posterior a todas as já vistas —, porque o boot não
    /// passou pela preparação. Na recusa, nada muda.
    pub fn aplicar(&mut self, m: &Mudanca) -> Result<(), Recusa> {
        if m.versao() < self.proxima {
            return Err(Recusa::ForaDeOrdem);
        }
        if m.versao() > MAIOR_VERSAO {
            return Err(Recusa::Cheio);
        }
        match m {
            Mudanca::Gravado { caminho, dados, .. } => {
                self.conferir_lugar(caminho)?;
                self.conferir_tetos(caminho, dados.len())?;
                let novo = Objeto {
                    versao: m.versao(),
                    dados: dados.clone(),
                };
                match self.objetos.insert(caminho.clone(), novo) {
                    Some(antigo) => {
                        self.por_versao.remove(&antigo.versao);
                        self.bytes -= antigo.dados.len();
                    }
                    None => self.entrar_nos_diretorios(caminho),
                }
                self.por_versao.insert(m.versao(), caminho.clone());
                self.bytes += dados.len();
            }
            Mudanca::Apagado { caminho, .. } => {
                let o = self
                    .objetos
                    .remove(caminho.as_str())
                    .ok_or(Recusa::NaoExiste)?;
                self.por_versao.remove(&o.versao);
                self.bytes -= o.dados.len();
                self.sair_dos_diretorios(caminho);
            }
        }
        self.proxima = m.versao() + 1;
        Ok(())
    }

    /// Um arquivo novo em `c`: cada diretório acima dele passa a ter mais
    /// um, e o que não existia nasce com um número novo.
    fn entrar_nos_diretorios(&mut self, c: &str) {
        for d in Self::acima(c) {
            match self.diretorios.get_mut(d) {
                Some(dir) => dir.arquivos += 1,
                None => {
                    let id = self.proximo_diretorio;
                    self.proximo_diretorio += 1;
                    self.diretorios
                        .insert(String::from(d), Diretorio { id, arquivos: 1 });
                    self.por_diretorio.insert(id, String::from(d));
                }
            }
        }
    }

    /// O arquivo em `c` saiu: cada diretório acima tem um a menos, e o que
    /// fica vazio deixa de existir.
    fn sair_dos_diretorios(&mut self, c: &str) {
        for d in Self::acima(c) {
            let vazio = match self.diretorios.get_mut(d) {
                Some(dir) => {
                    dir.arquivos -= 1;
                    dir.arquivos == 0
                }
                None => false,
            };
            if vazio && let Some(dir) = self.diretorios.remove(d) {
                self.por_diretorio.remove(&dir.id);
            }
        }
    }

    /// Para os testes: as contas de dentro conferem com os arquivos — cada
    /// diretório conta os arquivos abaixo dele, cada versão aponta para o
    /// arquivo que a tem, e os bytes somam o conteúdo.
    pub fn coerente(&self) -> bool {
        let bytes: usize = self.objetos.values().map(|o| o.dados.len()).sum();
        let versoes = self.por_versao.len() == self.objetos.len()
            && self
                .objetos
                .iter()
                .all(|(c, o)| self.por_versao.get(&o.versao) == Some(c));
        let mut contados: BTreeMap<&str, usize> = BTreeMap::new();
        for c in self.objetos.keys() {
            for d in Self::acima(c) {
                *contados.entry(d).or_default() += 1;
            }
        }
        let diretorios = contados.len() == self.diretorios.len()
            && contados.iter().all(|(d, n)| {
                self.diretorios
                    .get(*d)
                    .is_some_and(|dir| dir.arquivos == *n && self.diretorio(dir.id) == Some(d))
            })
            && self.por_diretorio.len() == self.diretorios.len();
        bytes == self.bytes && versoes && diretorios
    }
}

#[cfg(test)]
mod testes;
