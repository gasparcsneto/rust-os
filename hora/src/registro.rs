//! O registro de fontes de hora: `/etc/duke/tempo`.
//!
//! As fontes em que o relógio civil confia — o nome, o destino e a chave
//! Ed25519 de cada uma — e as regras do quórum, do salto e da incerteza. É
//! da imagem, como o registro de editores: ninguém o escreve em tempo de
//! execução, e trocar de fonte ou de chave é uma imagem nova. A chave nunca
//! se aprende da rede.
//!
//! # O formato
//!
//! ```text
//! # comentário
//! fonte bancada-a udp:10.0.2.2:5319 ed25519:<64 dígitos hexadecimais>
//! fonte bancada-b udp:10.0.2.2:5320 ed25519:<64 dígitos hexadecimais>
//! fonte bancada-c udp:10.0.2.2:5321 ed25519:<64 dígitos hexadecimais>
//! quorum 2
//! salto 86400
//! incerteza 60
//! ```
//!
//! - `fonte <nome> <destino> <chave>`, até [`MAIS_FONTES`]:
//!   - o nome segue a regra dos nomes da política: minúsculas, dígitos,
//!     `-`, `_` e `.`, até 32;
//!   - o destino é UDP, na forma normal da política
//!     ([`politica::endereco`]) — o mesmo texto que o gate decide para
//!     `net.connect`. A porta é a de cada fonte;
//!   - a chave é a raiz Ed25519 da fonte: `ed25519:` e 64 dígitos
//!     hexadecimais minúsculos. Uma que não é ponto da curva, ou que é de
//!     ordem pequena, é recusada aqui, e não descoberta na primeira
//!     resposta que não confere;
//!   - nome, destino e chave não se repetem. A mesma chave em duas fontes
//!     contaria uma vez no quórum, e o registro diria mais fontes do que há.
//! - `quorum <k>`: quantas chaves diferentes precisam concordar para o
//!   relógio se mover. Obrigatória, uma vez, de [`MENOR_QUORUM`] a
//!   [`MAIS_FONTES`]. **k ≥ 2 sempre**: uma fonte sozinha nunca move o
//!   relógio. Com k maior que o número de fontes, o registro vale — as
//!   respostas são conferidas e registradas —, e o relógio nunca se move:
//!   ver [`Registro::move_o_relogio`].
//! - `salto <segundos>`: o teto do salto automático para a frente. Acima
//!   dele, o salto fica pendente, esperando `time.confirm`. De
//!   [`MENOR_SALTO_S`] a [`MAIOR_SALTO_S`]; sem a linha, um dia.
//! - `incerteza <segundos>`: o teto da incerteza. Acima dele, a hora está
//!   vencida. De [`MENOR_INCERTEZA_S`] — o maior raio aceito de uma
//!   resposta — a [`MAIOR_INCERTEZA_S`]; sem a linha, 60 s.
//!
//! **Qualquer erro recusa o registro inteiro**, com a linha: um registro
//! meio lido seria uma confiança que ninguém escreveu. Recusado ou ausente,
//! não há fonte nenhuma, e nenhuma autorização a mais: o serviço de hora
//! não tem com quem falar, e o relógio civil fica no RTC.
//!
//! # A coerência com a política
//!
//! O registro diz em quem confiar; a política, com quem o serviço de hora
//! fala. [`Registro::conferir_com`] confere que os dois dizem o mesmo: a
//! política dá papel ao serviço `hora` (a linha `servico`), o papel tem
//! `time.sync`, e alcança com `net.connect` o destino de cada fonte —
//! pela mesma conta do gate, [`Politica::decidir`].
//!
//! A coerência é **conferência de configuração, e não autorização**. Quem
//! impede o serviço de falar com uma fonte sem destino na política é o
//! gate, a cada `net.connect`, e a recusa fica gravada. O `xtask` recusa
//! pôr na imagem um registro incoerente; o kernel confere no boot e avisa,
//! sem tirar fontes: a política muda em tempo de execução (um
//! `policy.write` que corta uma fonte), e o gate decide com a de agora.

use core::fmt;

use politica::endereco::{self, Destino, Protocolo};
use politica::{Codigo, Permissao, Politica};

use crate::disciplina::Parametros;

/// Onde a imagem guarda o registro.
pub const CAMINHO: &str = "/etc/duke/tempo";

/// O serviço da política que fala com as fontes — a linha `servico hora`.
pub const SERVICO: &str = "hora";

/// Quantas fontes cabem no registro: tantas quantas cabem numa rodada.
pub const MAIS_FONTES: usize = crate::quorum::MAIS_AMOSTRAS;

/// O menor quórum: duas chaves. Uma fonte sozinha nunca move o relógio.
pub const MENOR_QUORUM: u64 = 2;

/// O menor teto do salto automático, em segundos. Com ele, todo salto para
/// a frente espera uma pessoa.
pub const MENOR_SALTO_S: u64 = 1;

/// O maior teto do salto automático, em segundos: um dia. Acima disso, k
/// fontes comprometidas moveriam a hora mais longe sem ninguém ver.
pub const MAIOR_SALTO_S: u64 = 86_400;

/// O menor teto da incerteza, em segundos: o maior raio aceito de uma
/// resposta. Abaixo disso, uma rodada recém-acordada já nasceria vencida.
pub const MENOR_INCERTEZA_S: u64 = 10;

/// O maior teto da incerteza, em segundos: dez minutos. Acima disso, quem
/// lê o civil o tomaria por válido com uma margem que ninguém pediu.
pub const MAIOR_INCERTEZA_S: u64 = 600;

/// O prefixo da chave de uma fonte: o tipo dela, escrito.
pub const PREFIXO_DA_CHAVE: &str = "ed25519:";

const MAIOR_NOME: usize = 32;
// `udp:255.255.255.255:65535` tem 25 caracteres.
const MAIOR_DESTINO: usize = 32;

/// Uma fonte do registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fonte {
    nome: [u8; MAIOR_NOME],
    tamanho_do_nome: u8,
    endereco: Destino,
    destino: [u8; MAIOR_DESTINO],
    tamanho_do_destino: u8,
    chave: [u8; 32],
}

impl Fonte {
    const VAZIA: Fonte = Fonte {
        nome: [0; MAIOR_NOME],
        tamanho_do_nome: 0,
        endereco: Destino {
            protocolo: Protocolo::Udp,
            ip: [0; 4],
            porta: 0,
        },
        destino: [0; MAIOR_DESTINO],
        tamanho_do_destino: 0,
        chave: [0; 32],
    };

    /// O nome, como o registro o escreve.
    pub fn nome(&self) -> &str {
        texto(&self.nome[..usize::from(self.tamanho_do_nome)])
    }

    /// O destino, na forma normal da política: o recurso de `net.connect`.
    pub fn destino(&self) -> &str {
        texto(&self.destino[..usize::from(self.tamanho_do_destino)])
    }

    /// O destino, lido.
    pub const fn endereco(&self) -> Destino {
        self.endereco
    }

    /// A raiz Ed25519 da fonte: a chave fixada, contra a qual a delegação
    /// de cada resposta é conferida.
    pub const fn chave(&self) -> &[u8; 32] {
        &self.chave
    }
}

/// Os bytes guardados são sempre texto: vieram de um `&str`, inteiros.
fn texto(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

/// O registro lido e conferido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registro {
    fontes: [Fonte; MAIS_FONTES],
    quantas: usize,
    quorum: u64,
    salto_s: u64,
    incerteza_s: u64,
}

/// Um erro de leitura, com a linha — 0 para o que só se vê com tudo lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Erro {
    pub linha: usize,
    pub tipo: ErroTipo,
}

/// O que estava errado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroTipo {
    /// Uma linha que não começa com `fonte`, `quorum`, `salto` nem
    /// `incerteza`.
    LinhaDesconhecida,
    /// Falta algo na linha, ou sobra.
    Sintaxe,
    /// Um nome de fonte fora da regra.
    NomeInvalido,
    /// Um destino que não se lê, ou fora da forma normal.
    DestinoInvalido,
    /// Um destino TCP: as fontes falam UDP.
    DestinoNaoUdp,
    /// Uma chave sem o prefixo, ou que não são 64 dígitos minúsculos.
    ChaveInvalida,
    /// Uma chave que não é ponto da curva, ou que é de ordem pequena.
    ChaveFraca,
    /// Um nome que outra fonte já tem.
    NomeRepetido,
    /// Um destino que outra fonte já tem.
    DestinoRepetido,
    /// Uma chave que outra fonte já tem.
    ChaveRepetida,
    /// Mais de [`MAIS_FONTES`] fontes.
    FontesDemais,
    /// Um número que não é decimal, com zero à esquerda, ou grande demais.
    Numero,
    /// Um quórum menor que [`MENOR_QUORUM`].
    QuorumAbaixoDoMinimo(u64),
    /// Um quórum maior que [`MAIS_FONTES`]: nunca haveria acordo.
    QuorumAcimaDoMaximo(u64),
    /// Um teto do salto fora de [`MENOR_SALTO_S`]..=[`MAIOR_SALTO_S`].
    SaltoForaDosLimites(u64),
    /// Um teto da incerteza fora de
    /// [`MENOR_INCERTEZA_S`]..=[`MAIOR_INCERTEZA_S`].
    IncertezaForaDosLimites(u64),
    /// Uma linha `quorum`, `salto` ou `incerteza` que já veio.
    Repetida(&'static str),
    /// Falta a linha `quorum`: o registro não diz quantas chaves movem o
    /// relógio.
    SemQuorum,
    /// Nenhuma fonte.
    SemFontes,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.linha > 0 {
            write!(f, "linha {}: ", self.linha)?;
        }
        match self.tipo {
            ErroTipo::LinhaDesconhecida => {
                f.write_str("linha desconhecida: so fonte, quorum, salto e incerteza")
            }
            ErroTipo::Sintaxe => f.write_str("linha incompleta ou com sobra"),
            ErroTipo::NomeInvalido => f.write_str("nome de fonte fora da regra"),
            ErroTipo::DestinoInvalido => f.write_str(
                "destino invalido: so `udp:<ipv4>:<porta>`, na forma normal, sem curinga",
            ),
            ErroTipo::DestinoNaoUdp => f.write_str("as fontes de hora falam UDP"),
            ErroTipo::ChaveInvalida => {
                f.write_str("chave invalida: `ed25519:` e 64 digitos hexadecimais minusculos")
            }
            ErroTipo::ChaveFraca => {
                f.write_str("chave que nao serve: fora da curva, ou de ordem pequena")
            }
            ErroTipo::NomeRepetido => f.write_str("nome de fonte repetido"),
            ErroTipo::DestinoRepetido => f.write_str("destino de fonte repetido"),
            ErroTipo::ChaveRepetida => f.write_str(
                "chave repetida: a mesma chave contaria uma vez no quorum, e o registro diria mais fontes do que ha",
            ),
            ErroTipo::FontesDemais => write!(f, "mais de {MAIS_FONTES} fontes"),
            ErroTipo::Numero => f.write_str("numero invalido"),
            ErroTipo::QuorumAbaixoDoMinimo(k) => write!(
                f,
                "quorum {k}: no minimo {MENOR_QUORUM} chaves; uma fonte sozinha nunca move o relogio"
            ),
            ErroTipo::QuorumAcimaDoMaximo(k) => {
                write!(f, "quorum {k}: no maximo {MAIS_FONTES}")
            }
            ErroTipo::SaltoForaDosLimites(s) => write!(
                f,
                "salto {s}: de {MENOR_SALTO_S} a {MAIOR_SALTO_S} segundos"
            ),
            ErroTipo::IncertezaForaDosLimites(s) => write!(
                f,
                "incerteza {s}: de {MENOR_INCERTEZA_S} a {MAIOR_INCERTEZA_S} segundos"
            ),
            ErroTipo::Repetida(palavra) => write!(f, "a linha `{palavra}` veio duas vezes"),
            ErroTipo::SemQuorum => f.write_str(
                "falta a linha `quorum`: o registro nao diz quantas chaves movem o relogio",
            ),
            ErroTipo::SemFontes => f.write_str("nenhuma fonte"),
        }
    }
}

/// Um decimal sem sinal e sem zero à esquerda — o próprio `0` vale.
fn numero(t: &str) -> Option<u64> {
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if t.len() > 1 && t.starts_with('0') {
        return None;
    }
    t.parse().ok()
}

/// `ed25519:` e exatamente 64 dígitos hexadecimais minúsculos.
fn chave(t: &str) -> Option<[u8; 32]> {
    let hex = t.strip_prefix(PREFIXO_DA_CHAVE)?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let digito = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut saida = [0u8; 32];
    for (i, [alto, baixo]) in hex.as_chunks::<2>().0.iter().enumerate() {
        saida[i] = digito(*alto)? << 4 | digito(*baixo)?;
    }
    Some(saida)
}

/// A chave serve de raiz: é ponto da curva, e não de ordem pequena — a
/// mesma conta que a conferência da resposta faz com ela.
pub fn chave_aceitavel(chave: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(chave).is_ok_and(|k| !k.is_weak())
}

/// Escreve num arranjo da pilha, sem alocar.
struct Pilha<const N: usize> {
    bytes: [u8; N],
    usados: usize,
}

impl<const N: usize> fmt::Write for Pilha<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let fim = self.usados.checked_add(s.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.usados..fim)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.usados = fim;
        Ok(())
    }
}

/// O destino de uma fonte: UDP, e na forma normal — a que o gate compara.
fn destino(t: &str) -> Result<(Destino, [u8; MAIOR_DESTINO], u8), ErroTipo> {
    let lido = endereco::ler(t).ok_or(ErroTipo::DestinoInvalido)?;
    let mut normal = Pilha::<MAIOR_DESTINO> {
        bytes: [0; MAIOR_DESTINO],
        usados: 0,
    };
    let [a, b, c, d] = lido.ip;
    fmt::Write::write_fmt(
        &mut normal,
        format_args!("{}{a}.{b}.{c}.{d}:{}", lido.protocolo.prefixo(), lido.porta),
    )
    .map_err(|_| ErroTipo::DestinoInvalido)?;
    if &normal.bytes[..normal.usados] != t.as_bytes() {
        return Err(ErroTipo::DestinoInvalido);
    }
    if lido.protocolo != Protocolo::Udp {
        return Err(ErroTipo::DestinoNaoUdp);
    }
    Ok((lido, normal.bytes, normal.usados as u8))
}

impl Registro {
    /// Lê o registro inteiro. Qualquer erro o recusa inteiro, com a linha.
    pub fn ler(texto_do_arquivo: &str) -> Result<Registro, Erro> {
        let mut r = Registro {
            fontes: [Fonte::VAZIA; MAIS_FONTES],
            quantas: 0,
            quorum: 0,
            salto_s: Parametros::PADRAO.salto_maximo_ms / 1000,
            incerteza_s: Parametros::PADRAO.teto_da_incerteza_ms / 1000,
        };
        let (mut quorum, mut salto, mut incerteza) = (false, false, false);
        for (i, linha) in texto_do_arquivo.lines().enumerate() {
            let erro = |tipo| Erro { linha: i + 1, tipo };
            let linha = linha.split('#').next().unwrap_or("").trim();
            if linha.is_empty() {
                continue;
            }
            let mut partes = linha.split_ascii_whitespace();
            let palavra = partes.next().unwrap_or("");
            match palavra {
                "fonte" => {
                    let (Some(nome), Some(onde), Some(raiz), None) =
                        (partes.next(), partes.next(), partes.next(), partes.next())
                    else {
                        return Err(erro(ErroTipo::Sintaxe));
                    };
                    let fonte = Self::fonte(nome, onde, raiz).map_err(erro)?;
                    for outra in r.fontes() {
                        if outra.nome() == fonte.nome() {
                            return Err(erro(ErroTipo::NomeRepetido));
                        }
                        if outra.destino() == fonte.destino() {
                            return Err(erro(ErroTipo::DestinoRepetido));
                        }
                        if outra.chave == fonte.chave {
                            return Err(erro(ErroTipo::ChaveRepetida));
                        }
                    }
                    let vaga = r
                        .fontes
                        .get_mut(r.quantas)
                        .ok_or(erro(ErroTipo::FontesDemais))?;
                    *vaga = fonte;
                    r.quantas += 1;
                }
                "quorum" | "salto" | "incerteza" => {
                    let (Some(valor), None) = (partes.next(), partes.next()) else {
                        return Err(erro(ErroTipo::Sintaxe));
                    };
                    let n = numero(valor).ok_or(erro(ErroTipo::Numero))?;
                    let (ja, tipo) = match palavra {
                        "quorum" => (&mut quorum, "quorum"),
                        "salto" => (&mut salto, "salto"),
                        _ => (&mut incerteza, "incerteza"),
                    };
                    if *ja {
                        return Err(erro(ErroTipo::Repetida(tipo)));
                    }
                    *ja = true;
                    match palavra {
                        "quorum" if n < MENOR_QUORUM => {
                            return Err(erro(ErroTipo::QuorumAbaixoDoMinimo(n)));
                        }
                        "quorum" if n > MAIS_FONTES as u64 => {
                            return Err(erro(ErroTipo::QuorumAcimaDoMaximo(n)));
                        }
                        "quorum" => r.quorum = n,
                        "salto" if !(MENOR_SALTO_S..=MAIOR_SALTO_S).contains(&n) => {
                            return Err(erro(ErroTipo::SaltoForaDosLimites(n)));
                        }
                        "salto" => r.salto_s = n,
                        _ if !(MENOR_INCERTEZA_S..=MAIOR_INCERTEZA_S).contains(&n) => {
                            return Err(erro(ErroTipo::IncertezaForaDosLimites(n)));
                        }
                        _ => r.incerteza_s = n,
                    }
                }
                _ => return Err(erro(ErroTipo::LinhaDesconhecida)),
            }
        }
        let geral = |tipo| Erro { linha: 0, tipo };
        if r.quantas == 0 {
            return Err(geral(ErroTipo::SemFontes));
        }
        if !quorum {
            return Err(geral(ErroTipo::SemQuorum));
        }
        Ok(r)
    }

    /// Uma linha `fonte`, conferida campo a campo.
    fn fonte(nome: &str, onde: &str, raiz: &str) -> Result<Fonte, ErroTipo> {
        if !politica::arquivo::nome_valido(nome) || nome.len() > MAIOR_NOME {
            return Err(ErroTipo::NomeInvalido);
        }
        let (endereco, texto_do_destino, tamanho_do_destino) = destino(onde)?;
        let chave = chave(raiz).ok_or(ErroTipo::ChaveInvalida)?;
        if !chave_aceitavel(&chave) {
            return Err(ErroTipo::ChaveFraca);
        }
        let mut f = Fonte::VAZIA;
        f.nome[..nome.len()].copy_from_slice(nome.as_bytes());
        f.tamanho_do_nome = nome.len() as u8;
        f.endereco = endereco;
        f.destino = texto_do_destino;
        f.tamanho_do_destino = tamanho_do_destino;
        f.chave = chave;
        Ok(f)
    }

    /// As fontes, na ordem do registro — a ordem da rodada.
    pub fn fontes(&self) -> &[Fonte] {
        &self.fontes[..self.quantas]
    }

    /// A fonte com este nome, e a posição dela.
    pub fn fonte_de_nome(&self, nome: &str) -> Option<(usize, &Fonte)> {
        self.fontes()
            .iter()
            .enumerate()
            .find(|(_, f)| f.nome() == nome)
    }

    /// Quantas chaves diferentes precisam concordar.
    pub const fn quorum(&self) -> u64 {
        self.quorum
    }

    /// O teto do salto automático para a frente, em segundos.
    pub const fn salto_s(&self) -> u64 {
        self.salto_s
    }

    /// O teto da incerteza, em segundos.
    pub const fn incerteza_s(&self) -> u64 {
        self.incerteza_s
    }

    /// Há fontes bastantes para um acordo: k ≤ n. Com k maior que o número
    /// de fontes, as respostas são conferidas e registradas, e o relógio
    /// nunca se move — uma fonte isolada nunca o move.
    pub fn move_o_relogio(&self) -> bool {
        self.quorum <= self.quantas as u64
    }

    /// Os parâmetros da disciplina, com os tetos do registro.
    pub fn parametros(&self) -> Parametros {
        Parametros {
            salto_maximo_ms: self.salto_s * 1000,
            teto_da_incerteza_ms: self.incerteza_s * 1000,
            ..Parametros::PADRAO
        }
    }

    /// O registro e a política dizem o mesmo: o serviço de hora tem papel,
    /// o papel tem `time.sync`, e alcança com `net.connect` o destino de
    /// cada fonte. A primeira incoerência, na ordem do registro.
    ///
    /// Não autoriza nada: ver a seção sobre a coerência no topo do módulo.
    pub fn conferir_com<'a>(&'a self, politica: &'a Politica) -> Result<(), Incoerencia<'a>> {
        let papel = politica.servico(SERVICO).ok_or(Incoerencia::SemServico)?;
        let codigo = politica.decidir(Some(papel), Permissao::TimeSync, None);
        if codigo != Codigo::Allow {
            return Err(Incoerencia::SemPermissao { papel, codigo });
        }
        match self.fontes_sem_destino(politica).next() {
            Some((fonte, codigo)) => Err(Incoerencia::DestinoNaoAutorizado {
                papel,
                fonte,
                codigo,
            }),
            None => Ok(()),
        }
    }

    /// Cada fonte cujo destino o papel do serviço de hora não alcança com
    /// `net.connect`, com o código da decisão. Sem a linha `servico hora`,
    /// todas — a decisão sem papel é `DENY_ROLE`.
    pub fn fontes_sem_destino<'a>(
        &'a self,
        politica: &'a Politica,
    ) -> impl Iterator<Item = (&'a Fonte, Codigo)> + 'a {
        let papel = politica.servico(SERVICO);
        self.fontes().iter().filter_map(move |f| {
            let codigo = politica.decidir(papel, Permissao::NetConnect, Some(f.destino()));
            (codigo != Codigo::Allow).then_some((f, codigo))
        })
    }
}

/// O registro e a política não dizem o mesmo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incoerencia<'a> {
    /// A política não tem a linha `servico hora`: o serviço não tem papel.
    SemServico,
    /// O papel do serviço não tem `time.sync`.
    SemPermissao { papel: &'a str, codigo: Codigo },
    /// O papel do serviço não alcança o destino desta fonte.
    DestinoNaoAutorizado {
        papel: &'a str,
        fonte: &'a Fonte,
        codigo: Codigo,
    },
}

impl fmt::Display for Incoerencia<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Incoerencia::SemServico => write!(
                f,
                "a politica nao tem a linha `servico {SERVICO}`: o servico de hora nao tem papel"
            ),
            Incoerencia::SemPermissao { papel, codigo } => write!(
                f,
                "o papel `{papel}` do servico de hora nao tem `time.sync` ({})",
                codigo.nome()
            ),
            Incoerencia::DestinoNaoAutorizado {
                papel,
                fonte,
                codigo,
            } => write!(
                f,
                "a fonte `{}` fala em `{}`, que o papel `{papel}` nao alcanca com `net.connect` ({})",
                fonte.nome(),
                fonte.destino(),
                codigo.nome()
            ),
        }
    }
}

/// O registro como texto que [`Registro::ler`] lê de volta igual: as fontes
/// na ordem, e cada parâmetro escrito, mesmo o de valor padrão.
impl fmt::Display for Registro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for fonte in self.fontes() {
            write!(
                f,
                "fonte {} {} {PREFIXO_DA_CHAVE}",
                fonte.nome(),
                fonte.destino()
            )?;
            for b in fonte.chave {
                write!(f, "{b:02x}")?;
            }
            f.write_str("\n")?;
        }
        writeln!(f, "quorum {}", self.quorum)?;
        writeln!(f, "salto {}", self.salto_s)?;
        writeln!(f, "incerteza {}", self.incerteza_s)
    }
}

#[cfg(test)]
mod testes;
