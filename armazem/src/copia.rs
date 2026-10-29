//! A cópia de segurança do armazém: o formato, como conta pura.
//!
//! # O que é
//!
//! Uma fotografia de uma subárvore do armazém — os diretórios, os arquivos
//! e o conteúdo deles, como estavam num instante —, selada para sair da
//! máquina e voltar **só para ela**. Só dados: nada do estado de autoridade
//! — pessoas, credenciais, política, lápides, chaves de assinatura,
//! mensagens, auditoria, o estado da atualização. Esse estado mora no
//! journal de estado, e voltá-lo a uma fotografia anterior é exatamente o
//! rollback que a âncora do TPM existe para recusar. Nem a identidade, nem
//! segredo nenhum: a cópia não tem como levá-los, porque não os tem.
//!
//! # O formato
//!
//! ```text
//! setor 0, em claro (512 bytes)
//!    0  "DUKECOP1"          a magia
//!    8  formato  u16 LE     [`FORMATO`]
//!   10  zeros    6 bytes
//!   16  a pública do Duke   32 bytes: de que máquina a cópia é
//!   48  zeros até o fim do setor
//! setor 1 em diante: uma base do journal — partes (`BASE`) e o fecho
//! (`BASE_FIM`) —, cifrada, autenticada e encadeada como qualquer registro
//! do pacote `diario`, sob a chave da cópia
//! ```
//!
//! A chave da cópia é derivada da chave do Duke, por um rótulo próprio —
//! quem a deriva é o kernel, e ela não sai dele —: só a identidade que fez
//! a cópia a abre. O setor em claro só diz de quem a cópia é, para a recusa
//! dizer por quê; o que ele diz é conferido de novo contra o cabeçalho
//! cifrado.
//!
//! As partes levam entradas — campos do `diario`, o tipo em dois bytes na
//! frente:
//!
//! | tipo | campos |
//! |---|---|
//! | [`tipo::CABECALHO`] | formato (2), pública (32), instalação (16), raiz, versão (8), geração (8), tempo (8) |
//! | [`tipo::DIRETORIO`] | caminho, versão (8) |
//! | [`tipo::ARQUIVO`] | caminho, versão (8), tamanho (8) |
//! | [`tipo::PEDACO`] | até [`MAIOR_PEDACO`] bytes do conteúdo do arquivo anterior |
//!
//! O fecho leva os totais: diretórios (8), arquivos (8), bytes (8).
//!
//! # As regras
//!
//! As mesmas na escrita e na leitura (`Regras`): o cabeçalho primeiro, e
//! uma vez; a raiz da cópia como primeiro nó; os nós em ordem estrita de
//! caminho, cada um com o pai já visto como diretório, nenhum abaixo de um
//! arquivo; os pedaços de cada arquivo logo depois dele, somando o tamanho
//! dele exatamente; cada versão anterior à da captura; o fecho com os
//! totais do que veio, e nada depois dele. O encadeamento do `diario` faz o
//! resto: um registro trocado de lugar, repetido, tirado, cortado ou
//! mexido não abre — e a cópia que não abre inteira é recusada inteira.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use diario::estado::{self as estado_do_diario, campos, ler_campos};
use diario::{Escritor, Interrompido, Meio, Parada, Percorrido, TAM_NONCE, TAM_SETOR};
use zeroize::Zeroize;

use crate::{MAIOR_VERSAO, caminho_valido, pai};

/// O começo de toda cópia.
pub const MAGIA: [u8; 8] = *b"DUKECOP1";
/// A versão do formato que este pacote escreve e lê.
pub const FORMATO: u16 = 1;
/// O maior pedaço de conteúdo numa entrada.
pub const MAIOR_PEDACO: usize = 60 * 1024;
/// Quantos nós uma cópia leva, no máximo: os objetos da maior cota da
/// política padrão, com folga. Um teto para a leitura não crescer sem fim.
pub const MAIS_NOS: u64 = 1 << 20;

/// Quanto uma parte leva de entradas: o que cabe num registro, com folga.
const TETO_DA_PARTE: usize = diario::MAIOR_CONTEUDO - 64;
/// Quantos setores o escritor da base admite: a cópia não mora numa
/// partição, e o limite dela é o de quem a guarda.
const SETORES_DA_BASE: u64 = u64::MAX / 1024;

/// Os tipos de entrada.
pub mod tipo {
    pub const CABECALHO: u16 = 1;
    pub const DIRETORIO: u16 = 2;
    pub const ARQUIVO: u16 = 3;
    pub const PEDACO: u16 = 4;
}

/// De que máquina a cópia é: a identidade e a instalação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origem {
    /// A pública do Duke — a que `system.info` mostra.
    pub publica: [u8; 32],
    /// O identificador da instalação: o que o journal de estado sorteou ao
    /// nascer.
    pub instalacao: [u8; 16],
}

/// O cabeçalho de uma cópia: de onde, de que subárvore, e de que instante.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cabecalho {
    pub origem: Origem,
    /// A raiz da cópia, relativa à raiz do armazém; vazia é o armazém
    /// inteiro.
    pub raiz: String,
    /// A versão que a próxima mudança do armazém levaria na captura: todo
    /// nó da cópia tem uma versão anterior a ela.
    pub versao: u64,
    /// A geração administrativa na captura.
    pub geracao: u64,
    /// O tempo lógico da captura, em segundos desde 1970.
    pub tempo: u64,
}

/// Os totais de uma cópia: o que o fecho diz.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totais {
    pub diretorios: u64,
    pub arquivos: u64,
    pub bytes: u64,
}

/// O que a leitura entrega, na ordem da cópia.
#[derive(Debug, PartialEq, Eq)]
pub enum Evento<'a> {
    /// O cabeçalho, conferido — sempre o primeiro.
    Cabecalho(&'a Cabecalho),
    /// Um diretório: o caminho relativo à raiz da cópia (vazio é ela).
    Diretorio { caminho: &'a str, versao: u64 },
    /// Um arquivo; o conteúdo vem nos pedaços seguintes.
    Arquivo {
        caminho: &'a str,
        versao: u64,
        tamanho: u64,
    },
    /// Um pedaço do conteúdo do arquivo anterior, em ordem.
    Pedaco(&'a [u8]),
    /// O conteúdo do arquivo anterior chegou inteiro.
    FimDoArquivo,
}

/// Uma cópia lida inteira: o cabeçalho, os totais e o identificador — o
/// elo do fecho, que nomeia exatamente esta cópia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lida {
    pub cabecalho: Cabecalho,
    pub totais: Totais,
    pub id: [u8; 32],
}

/// Uma cópia escrita inteira.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fechada {
    pub totais: Totais,
    pub id: [u8; 32],
    /// Quantos setores ela ocupa, o em claro junto.
    pub setores: u64,
}

/// Por que uma cópia não foi aceita. Nenhuma recusa aceita parte dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa<E> {
    /// Quem guarda a cópia não a entregou.
    Meio(&'static str),
    /// Não começa pela magia.
    NaoECopia,
    /// De um formato que este pacote não lê.
    Formato,
    /// Diz ser de outra identidade.
    OutraMaquina,
    /// Desta identidade, de outra instalação.
    OutraInstalacao,
    /// O primeiro registro não abre com a chave desta máquina.
    NaoAbre,
    /// Um registro, ou uma entrada, fora das regras.
    Estragada(&'static str),
    /// Acaba antes do fecho.
    Incompleta,
    /// Há bytes depois do fecho.
    Sobra,
    /// Quem leu recusou o que recebeu.
    Fora(E),
}

impl<E> Recusa<E> {
    /// A recusa, em palavras — sem a de quem leu, que tem as dela.
    pub fn motivo(&self) -> &'static str {
        match self {
            Recusa::Meio(m) | Recusa::Estragada(m) => m,
            Recusa::NaoECopia => "nao e uma copia do armazem do Duke",
            Recusa::Formato => "a copia e de um formato desconhecido",
            Recusa::OutraMaquina => "a copia e de outra maquina",
            Recusa::OutraInstalacao => "a copia e de outra instalacao",
            Recusa::NaoAbre => "a copia nao abre nesta maquina",
            Recusa::Incompleta => "a copia esta incompleta: falta o fecho",
            Recusa::Sobra => "ha bytes depois do fecho da copia",
            Recusa::Fora(_) => "quem leu a copia recusou",
        }
    }
}

/// O caminho, relativo à raiz do armazém, de `caminho` relativo à raiz
/// `raiz` da cópia.
pub fn no_armazem(raiz: &str, caminho: &str) -> String {
    match (raiz.is_empty(), caminho.is_empty()) {
        (true, _) => String::from(caminho),
        (false, true) => String::from(raiz),
        (false, false) => {
            let mut c = String::with_capacity(raiz.len() + 1 + caminho.len());
            c.push_str(raiz);
            c.push('/');
            c.push_str(caminho);
            c
        }
    }
}

/// As regras de uma cópia, conferidas entrada por entrada — as mesmas na
/// escrita e na leitura: uma cópia que o escritor deixa sair é uma que o
/// leitor aceita, e nenhuma outra.
#[derive(Debug)]
struct Regras {
    raiz: String,
    versao: u64,
    /// O caminho do último nó, relativo à raiz da cópia.
    ultimo: Option<String>,
    diretorios: BTreeSet<String>,
    /// A raiz da cópia é um arquivo: nada mais vem.
    raiz_e_arquivo: bool,
    /// Quanto falta do arquivo aberto.
    falta: Option<u64>,
    totais: Totais,
    fechada: bool,
}

impl Regras {
    fn nova(c: &Cabecalho) -> Result<Regras, &'static str> {
        if !c.raiz.is_empty() && !caminho_valido(&c.raiz) {
            return Err("a raiz da copia nao e do armazem");
        }
        if c.versao == 0 || c.versao > MAIOR_VERSAO.saturating_add(1) {
            return Err("a versao da captura e impossivel");
        }
        Ok(Regras {
            raiz: c.raiz.clone(),
            versao: c.versao,
            ultimo: None,
            diretorios: BTreeSet::new(),
            raiz_e_arquivo: false,
            falta: None,
            totais: Totais::default(),
            fechada: false,
        })
    }

    /// Um nó: um diretório (`tamanho` nenhum) ou um arquivo.
    fn no(&mut self, caminho: &str, versao: u64, tamanho: Option<u64>) -> Result<(), &'static str> {
        if self.fechada {
            return Err("um no depois do fecho");
        }
        if self.falta.is_some() {
            return Err("um no antes do fim do arquivo anterior");
        }
        if self.totais.diretorios + self.totais.arquivos >= MAIS_NOS {
            return Err("nos demais numa copia");
        }
        // A raiz do armazém não é nó, e tem a versão 0; todo outro nó tem
        // uma versão que o contador do armazém deu antes da captura.
        let raiz_do_armazem = caminho.is_empty() && self.raiz.is_empty();
        if versao >= self.versao || (versao == 0 && !raiz_do_armazem) {
            return Err("um no com versao que a captura nao tinha");
        }
        match &self.ultimo {
            None if !caminho.is_empty() => return Err("a copia nao comeca pela raiz dela"),
            None => {}
            Some(ultimo) => {
                if self.raiz_e_arquivo {
                    return Err("um no abaixo de um arquivo");
                }
                if caminho <= ultimo.as_str() {
                    return Err("nos fora de ordem, ou repetidos");
                }
                if !caminho_valido(caminho) {
                    return Err("um caminho que nao e do armazem");
                }
                if !self.diretorios.contains(pai(caminho)) {
                    return Err("um no sem o diretorio pai");
                }
            }
        }
        let completo = no_armazem(&self.raiz, caminho);
        if completo.is_empty() {
            if tamanho.is_some() {
                return Err("a raiz do armazem e um diretorio");
            }
        } else if !caminho_valido(&completo) {
            return Err("um caminho fundo demais para o armazem");
        }
        match tamanho {
            None => {
                self.diretorios.insert(String::from(caminho));
                self.totais.diretorios += 1;
            }
            Some(n) => {
                self.totais.arquivos += 1;
                self.raiz_e_arquivo |= caminho.is_empty();
                if n > 0 {
                    self.falta = Some(n);
                }
            }
        }
        self.ultimo = Some(String::from(caminho));
        Ok(())
    }

    /// Um pedaço de `n` bytes. `true` quando ele fecha o arquivo.
    fn pedaco(&mut self, n: usize) -> Result<bool, &'static str> {
        if n == 0 || n > MAIOR_PEDACO {
            return Err("um pedaco vazio, ou maior que o teto");
        }
        let falta = self.falta.ok_or("um pedaco fora de um arquivo")?;
        let n = n as u64;
        if n > falta {
            return Err("pedacos alem do tamanho do arquivo");
        }
        self.totais.bytes = self
            .totais
            .bytes
            .checked_add(n)
            .ok_or("bytes demais numa copia")?;
        self.falta = (n < falta).then_some(falta - n);
        Ok(n == falta)
    }

    fn fechar(&mut self, totais: &Totais) -> Result<(), &'static str> {
        if self.fechada {
            return Err("dois fechos");
        }
        if self.falta.is_some() {
            return Err("o fecho antes do fim de um arquivo");
        }
        if self.ultimo.is_none() {
            return Err("uma copia sem a raiz dela");
        }
        if *totais != self.totais {
            return Err("os totais do fecho nao conferem");
        }
        self.fechada = true;
        Ok(())
    }
}

fn com_tipo(t: u16, resto: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let t = t.to_le_bytes();
    let mut todos: Vec<&[u8]> = Vec::with_capacity(resto.len() + 1);
    todos.push(&t);
    todos.extend_from_slice(resto);
    campos(&todos)
}

fn entrada_do_cabecalho(c: &Cabecalho) -> Result<Vec<u8>, &'static str> {
    com_tipo(
        tipo::CABECALHO,
        &[
            &FORMATO.to_le_bytes(),
            &c.origem.publica,
            &c.origem.instalacao,
            c.raiz.as_bytes(),
            &c.versao.to_le_bytes(),
            &c.geracao.to_le_bytes(),
            &c.tempo.to_le_bytes(),
        ],
    )
}

fn fecho(t: &Totais) -> Result<Vec<u8>, &'static str> {
    campos(&[
        &t.diretorios.to_le_bytes(),
        &t.arquivos.to_le_bytes(),
        &t.bytes.to_le_bytes(),
    ])
}

/// O setor em claro de uma cópia desta pública.
fn setor_claro(publica: &[u8; 32]) -> [u8; TAM_SETOR] {
    let mut s = [0u8; TAM_SETOR];
    s[..8].copy_from_slice(&MAGIA);
    s[8..10].copy_from_slice(&FORMATO.to_le_bytes());
    s[16..48].copy_from_slice(publica);
    s
}

/// A escrita de uma cópia: o setor em claro, as partes e o fecho, cada um
/// entregue a `saida` assim que está pronto — setores inteiros, em ordem.
/// `nonce` dá um nonce sorteado por registro.
///
/// Nada do conteúdo fica para trás: a entrada de um pedaço é zerada depois
/// de selada.
pub struct Escrita<'k, N, S> {
    chave: &'k [u8; 32],
    nonce: N,
    saida: S,
    base: diario::Base,
    entradas: Vec<Vec<u8>>,
    tamanho: usize,
    tempo: u64,
    regras: Regras,
    setores: u64,
}

impl<'k, N, S> Escrita<'k, N, S>
where
    N: FnMut() -> Result<[u8; TAM_NONCE], &'static str>,
    S: FnMut(&[u8]) -> Result<(), &'static str>,
{
    /// Começa a cópia descrita por `cabecalho`.
    pub fn comecar(
        chave: &'k [u8; 32],
        cabecalho: &Cabecalho,
        nonce: N,
        mut saida: S,
    ) -> Result<Self, &'static str> {
        let regras = Regras::nova(cabecalho)?;
        let base =
            Escritor::depois_de(&Percorrido::vazio(), 0, SETORES_DA_BASE).base(SETORES_DA_BASE)?;
        saida(&setor_claro(&cabecalho.origem.publica))?;
        let mut e = Escrita {
            chave,
            nonce,
            saida,
            base,
            entradas: Vec::new(),
            tamanho: 0,
            tempo: cabecalho.tempo,
            regras,
            setores: 1,
        };
        e.entrada(entrada_do_cabecalho(cabecalho)?)?;
        Ok(e)
    }

    fn entrada(&mut self, e: Vec<u8>) -> Result<(), &'static str> {
        if self.tamanho + e.len() + 2 > TETO_DA_PARTE && !self.entradas.is_empty() {
            self.parte()?;
        }
        self.tamanho += e.len() + 2;
        self.entradas.push(e);
        Ok(())
    }

    /// As entradas juntadas viram uma parte, que sai.
    fn parte(&mut self) -> Result<(), &'static str> {
        let mut dados = campos(&self.entradas.iter().map(Vec::as_slice).collect::<Vec<_>>());
        for e in &mut self.entradas {
            e.zeroize();
        }
        self.entradas.clear();
        self.tamanho = 0;
        let parte = (|| {
            let dados = dados.as_ref().map_err(|m| *m)?;
            let nonce = (self.nonce)()?;
            self.base.parte(self.chave, nonce, 0, self.tempo, dados)
        })();
        if let Ok(d) = &mut dados {
            d.zeroize();
        }
        let parte = parte?;
        (self.saida)(&parte.bytes)?;
        self.setores += (parte.bytes.len() / TAM_SETOR) as u64;
        Ok(())
    }

    /// Um diretório da cópia, pelo caminho relativo à raiz dela.
    pub fn diretorio(&mut self, caminho: &str, versao: u64) -> Result<(), &'static str> {
        self.regras.no(caminho, versao, None)?;
        self.entrada(com_tipo(
            tipo::DIRETORIO,
            &[caminho.as_bytes(), &versao.to_le_bytes()],
        )?)
    }

    /// Um arquivo da cópia; o conteúdo, em seguida, por [`Escrita::conteudo`].
    pub fn arquivo(
        &mut self,
        caminho: &str,
        versao: u64,
        tamanho: u64,
    ) -> Result<(), &'static str> {
        self.regras.no(caminho, versao, Some(tamanho))?;
        self.entrada(com_tipo(
            tipo::ARQUIVO,
            &[
                caminho.as_bytes(),
                &versao.to_le_bytes(),
                &tamanho.to_le_bytes(),
            ],
        )?)
    }

    /// Mais conteúdo do arquivo aberto — em pedaços de qualquer tamanho.
    pub fn conteudo(&mut self, mut bytes: &[u8]) -> Result<(), &'static str> {
        while !bytes.is_empty() {
            let n = bytes.len().min(MAIOR_PEDACO);
            self.regras.pedaco(n)?;
            self.entrada(com_tipo(tipo::PEDACO, &[&bytes[..n]])?)?;
            bytes = &bytes[n..];
        }
        Ok(())
    }

    /// Fecha a cópia: a última parte, e o fecho com os totais.
    pub fn fechar(mut self) -> Result<Fechada, &'static str> {
        let totais = self.regras.totais;
        self.regras.fechar(&totais)?;
        if !self.entradas.is_empty() {
            self.parte()?;
        }
        let Escrita {
            chave,
            mut nonce,
            mut saida,
            base,
            tempo,
            setores,
            ..
        } = self;
        let fechada = base.fechar(chave, nonce()?, 0, tempo, &fecho(&totais)?)?;
        saida(&fechada.bytes)?;
        Ok(Fechada {
            totais,
            id: fechada.elo(),
            setores: setores + (fechada.bytes.len() / TAM_SETOR) as u64,
        })
    }
}

/// Os setores de uma cópia a partir do segundo: a base do journal dela.
struct DepoisDoClaro<'m, M> {
    meio: &'m mut M,
}

impl<M: Meio> Meio for DepoisDoClaro<'_, M> {
    fn setores(&self) -> u64 {
        self.meio.setores().saturating_sub(1)
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        self.meio.ler(setor + 1, destino)
    }

    fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
        Err("uma copia se le, e nao se escreve")
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
}

/// O motivo do `diario` para um registro que passa do fim de onde ele mora.
const ALEM_DO_FIM: &str = "o registro passa do fim da particao";

/// Por que a leitura parou dentro de um registro: as regras, ou quem lê.
enum Parou<E> {
    Regra(&'static str),
    Fora(E),
}

impl<E> From<&'static str> for Parou<E> {
    fn from(m: &'static str) -> Self {
        Parou::Regra(m)
    }
}

fn u64_de(b: &[u8]) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(
        b.try_into().map_err(|_| "numero que nao tem 8 bytes")?,
    ))
}

fn texto(b: &[u8]) -> Result<&str, &'static str> {
    core::str::from_utf8(b).map_err(|_| "texto que nao e utf-8")
}

fn cabecalho_de(campos: &[&[u8]]) -> Result<Cabecalho, &'static str> {
    let [formato, publica, instalacao, raiz, versao, geracao, tempo] = campos else {
        return Err("um cabecalho com os campos errados");
    };
    if *formato != FORMATO.to_le_bytes() {
        return Err("um cabecalho de outro formato");
    }
    Ok(Cabecalho {
        origem: Origem {
            publica: (*publica)
                .try_into()
                .map_err(|_| "uma publica sem 32 bytes")?,
            instalacao: (*instalacao)
                .try_into()
                .map_err(|_| "uma instalacao sem 16 bytes")?,
        },
        raiz: String::from(texto(raiz)?),
        versao: u64_de(versao)?,
        geracao: u64_de(geracao)?,
        tempo: u64_de(tempo)?,
    })
}

/// Lê e confere uma cópia inteira de `meio` — o setor em claro primeiro —,
/// com a chave da cópia desta máquina, esperando a `origem` desta máquina.
/// Cada nó e cada pedaço vão a `f` em ordem, assim que conferidos; o que
/// `f` fez com eles só vale se a leitura terminar em `Ok`: uma recusa
/// depois de um pedaço entregue é a cópia inteira recusada.
pub fn ler<M: Meio, E>(
    meio: &mut M,
    chave: &[u8; 32],
    origem: &Origem,
    mut f: impl FnMut(Evento<'_>) -> Result<(), E>,
) -> Result<Lida, Recusa<E>> {
    let total = meio.setores();
    if total < 2 {
        return Err(Recusa::Incompleta);
    }
    let mut claro = [0u8; TAM_SETOR];
    meio.ler(0, &mut claro).map_err(Recusa::Meio)?;
    if claro[..8] != MAGIA {
        return Err(Recusa::NaoECopia);
    }
    if claro[8..10] != FORMATO.to_le_bytes() {
        return Err(Recusa::Formato);
    }
    if claro[10..16].iter().chain(&claro[48..]).any(|&b| b != 0) {
        return Err(Recusa::Estragada(
            "o setor em claro tem bytes fora do lugar",
        ));
    }
    if claro[16..48] != origem.publica {
        return Err(Recusa::OutraMaquina);
    }
    let mut regras: Option<Regras> = None;
    let mut cabecalho: Option<Cabecalho> = None;
    let mut fechada: Option<Totais> = None;
    let mut outra_instalacao = false;
    let mut depois = DepoisDoClaro { meio };
    let percorrido = diario::percorrer(&mut depois, chave, |r| -> Result<(), Parou<E>> {
        if fechada.is_some() {
            return Err(Parou::Regra("um registro depois do fecho"));
        }
        match r.tipo {
            estado_do_diario::tipo::BASE => {
                for e in ler_campos(&r.conteudo)? {
                    let c = ler_campos(e)?;
                    let (t, resto) = c.split_first().ok_or("uma entrada vazia")?;
                    let t = u16::from_le_bytes((*t).try_into().map_err(|_| "um tipo sem 2 bytes")?);
                    let Some(rs) = regras.as_mut() else {
                        if t != tipo::CABECALHO {
                            return Err(Parou::Regra("a copia nao comeca pelo cabecalho"));
                        }
                        let cab = cabecalho_de(resto)?;
                        if cab.origem.publica != origem.publica {
                            return Err(Parou::Regra("o cabecalho e o setor em claro divergem"));
                        }
                        if cab.origem.instalacao != origem.instalacao {
                            outra_instalacao = true;
                            return Err(Parou::Regra("de outra instalacao"));
                        }
                        regras = Some(Regras::nova(&cab)?);
                        f(Evento::Cabecalho(&cab)).map_err(Parou::Fora)?;
                        cabecalho = Some(cab);
                        continue;
                    };
                    match (t, resto) {
                        (tipo::DIRETORIO, [caminho, versao]) => {
                            let (caminho, versao) = (texto(caminho)?, u64_de(versao)?);
                            rs.no(caminho, versao, None)?;
                            f(Evento::Diretorio { caminho, versao }).map_err(Parou::Fora)?;
                        }
                        (tipo::ARQUIVO, [caminho, versao, tamanho]) => {
                            let (caminho, versao, tamanho) =
                                (texto(caminho)?, u64_de(versao)?, u64_de(tamanho)?);
                            rs.no(caminho, versao, Some(tamanho))?;
                            f(Evento::Arquivo {
                                caminho,
                                versao,
                                tamanho,
                            })
                            .map_err(Parou::Fora)?;
                            if tamanho == 0 {
                                f(Evento::FimDoArquivo).map_err(Parou::Fora)?;
                            }
                        }
                        (tipo::PEDACO, [bytes]) => {
                            let fim = rs.pedaco(bytes.len())?;
                            f(Evento::Pedaco(bytes)).map_err(Parou::Fora)?;
                            if fim {
                                f(Evento::FimDoArquivo).map_err(Parou::Fora)?;
                            }
                        }
                        (tipo::CABECALHO, _) => return Err(Parou::Regra("dois cabecalhos")),
                        _ => return Err(Parou::Regra("uma entrada desconhecida ou malformada")),
                    }
                }
                Ok(())
            }
            estado_do_diario::tipo::BASE_FIM => {
                let [d, a, b] = estado_do_diario::exatamente::<3>(&r.conteudo)?;
                let totais = Totais {
                    diretorios: u64_de(d)?,
                    arquivos: u64_de(a)?,
                    bytes: u64_de(b)?,
                };
                regras
                    .as_mut()
                    .ok_or("o fecho antes do cabecalho")?
                    .fechar(&totais)?;
                fechada = Some(totais);
                Ok(())
            }
            _ => Err(Parou::Regra("um registro que nao e de uma copia")),
        }
    });
    let p = match percorrido {
        Ok(p) => p,
        Err(Interrompido::Meio(m)) => return Err(Recusa::Meio(m)),
        Err(Interrompido::Recusado {
            motivo: Parou::Fora(e),
            ..
        }) => return Err(Recusa::Fora(e)),
        Err(Interrompido::Recusado { .. }) if outra_instalacao => {
            return Err(Recusa::OutraInstalacao);
        }
        Err(Interrompido::Recusado {
            motivo: Parou::Regra(m),
            ..
        }) => return Err(Recusa::Estragada(m)),
    };
    // Um registro que diz ter mais setores do que a cópia tem é uma cópia
    // cortada — um envio que parou no meio —, e não uma que não abre.
    if let Parada::Ilegivel {
        motivo: ALEM_DO_FIM,
        ..
    } = p.parada
    {
        return Err(Recusa::Incompleta);
    }
    if p.quantos == 0 {
        return Err(match p.parada {
            Parada::Ilegivel { .. } => Recusa::NaoAbre,
            _ => Recusa::Incompleta,
        });
    }
    if p.primeiro_tipo != Some(estado_do_diario::tipo::BASE) {
        return Err(Recusa::Estragada("a copia nao comeca por uma parte"));
    }
    let (Some(totais), Some(cabecalho)) = (fechada, cabecalho) else {
        return Err(match p.parada {
            Parada::Ilegivel { motivo, .. } => Recusa::Estragada(motivo),
            _ => Recusa::Incompleta,
        });
    };
    if p.parada != Parada::Fim || p.proximo_setor != total - 1 {
        return Err(Recusa::Sobra);
    }
    Ok(Lida {
        cabecalho,
        totais,
        id: p.elo,
    })
}
