//! A política: o arquivo, a validação, a decisão e as mudanças.
//!
//! # O formato
//!
//! ```text
//! # comentário
//! papel observador agent.read system.read log.read ui.read
//! papel operador @observador ui.act process.run net.send fs.read
//! recurso operador fs.read /dados /bin /programas
//! recurso operador process.run /bin /programas
//! taxa operador 50 100
//! apertos 10 10000
//! serial sistema
//! local sistema
//! ```
//!
//! - `papel <nome> <item>...`: um item é uma permissão do vocabulário ou
//!   `@<papel>`, a inclusão de outro papel. A inclusão traz só as permissões
//!   **não sensíveis** do outro: uma sensível precisa estar escrita em cada
//!   papel que a tem. Não há curinga — `*` é um erro com nome próprio.
//! - `recurso <papel> <permissão> <prefixo>...`: o alcance de uma
//!   permissão cujo recurso é um caminho. **Obrigatório** para cada papel
//!   que tem uma delas: sem a linha, o papel não seria limitado — e "sem
//!   limite" seria um curinga escrito pela ausência. O alcance inteiro se
//!   escreve: `recurso sistema fs.read /`. A mesma linha diz o alcance de
//!   `message.send` — os papéis destinatários, `papel:<nome>` — e o de
//!   `net.connect` — os destinos de rede, cada um inteiro e na forma
//!   normal, `tcp:<ipv4>:<porta>` ([`crate::endereco`]). Nos dois, uma
//!   lista enumerada: o que não está escrito não é alcançado.
//! - `taxa <papel> <por segundo> <rajada>`: o balde de pedidos do papel.
//! - `processos <papel> <quantos>`: a cota de processos vivos de cada
//!   titular do papel — uma sessão de agente, uma de pessoa, o sistema —,
//!   de 1 a 64; sem a linha, 4.
//! - `mensagens <papel> <por remetente> <por caixa>`: as cotas de mensagens
//!   do papel — quantas vivas cada titular dele tem como remetente, somando
//!   todas as caixas, e quantas a caixa dele guarda. De 1 até os tetos da
//!   tabela, 32 e 64; sem a linha, 8 e 32. O total de vivas, 128, é da
//!   imagem — ver [`crate::mensagens`].
//! - `armazem <papel> <bytes> <objetos>`: a cota de armazém de cada dono
//!   do papel — cada identidade —: os bytes de conteúdo e os objetos
//!   (arquivos e diretórios) que ele ocupa. De 1 até 1 TiB e 2^24; sem a
//!   linha, nenhuma — quem não tem cota não guarda nada, tenha ou não
//!   `fs.write`. Um `policy.write` que a aumente cabe no teto de quem
//!   delega.
//! - `quorum <operação> <M> <N>`: a operação exige que M credenciais de
//!   administrador distintas, de um grupo de N, provem o mesmo pedido. De
//!   2 até N, e N até [`MAIOR_GRUPO`]; só para as operações de
//!   [`OPERACOES_DE_QUORUM`]. Só a imagem a escreve: um `policy.write` que
//!   baixasse o M seria uma credencial só desfazendo o quórum.
//! - `apertos <quantos> <janela em ms>`: apertos de mão por porta.
//! - `serial <papel>`: o papel da sessão 0. Obrigatória.
//! - `local <papel>`: o papel da autoridade local — os processos do
//!   sistema. Obrigatória. A pessoa num console não é a autoridade local:
//!   decide pelo papel dela no registro de pessoas. Ela não é exceção à política:
//!   decide pela mesma conta, com as permissões que o papel enumera.
//!
//! # Validar antes de valer
//!
//! O arquivo inteiro é lido, e só então conferido: papéis citados existem, a
//! inclusão não tem ciclo, um `recurso` limita uma permissão que o papel tem
//! e cujo recurso é caminho. Qualquer erro recusa a política inteira, com a
//! linha — e quem carrega fica com a de emergência, ver
//! [`Politica::emergencia`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::caminho;
use crate::codigo::Codigo;
use crate::permissao::Permissao;

/// O balde de pedidos de um papel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taxa {
    pub por_segundo: u32,
    pub rajada: u32,
}

/// A taxa de um papel que não declara a sua: pouca, de propósito.
pub const TAXA_PADRAO: Taxa = Taxa {
    por_segundo: 10,
    rajada: 20,
};

/// Quantos processos vivos um titular de um papel que não declara a sua
/// cota pode ter.
pub const PROCESSOS_PADRAO: u32 = 4;

/// A maior cota de processos que a política aceita.
pub const MAIS_PROCESSOS: u32 = 64;

/// As operações que exigem quórum — e que só existem com a linha `quorum`
/// delas na política.
pub const OPERACOES_DE_QUORUM: &[&str] = &["admin.revoke"];

/// O maior grupo de credenciais de um quórum.
pub const MAIOR_GRUPO: u8 = 16;

/// O piso do quórum de uma operação crítica: o mínimo de credenciais e a
/// fração mínima do grupo, `num/den`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piso {
    pub operacao: &'static str,
    pub m_minimo: u8,
    pub num: u8,
    pub den: u8,
}

/// Os pisos das operações de quórum, invariantes da política.
///
/// `admin.revoke`: pelo menos 2 credenciais, e pelo menos dois terços do
/// grupo — a proteção do 2 de 3. Um 3 de 4 ou um 4 de 5 cabem; um 2 de 4 ou
/// um 3 de 5, não: neles, uma minoria do grupo revogaria as outras.
///
/// # Por que um invariante, e não só "o `policy.write` não escreve quórum"
///
/// Porque o `policy.write` recusar a linha `quorum` é uma regra de um
/// caminho, e o piso é uma propriedade da política, por qualquer caminho:
/// o arquivo da imagem, o do disco no boot, a de emergência e cada mudança
/// em tempo de execução passam por [`Politica::ler`] ou pela validação de
/// [`Politica::com_linha`], e a validação confere o piso. Uma política que o
/// baixasse não vigora — no boot vale a de emergência, e o `xtask` nem gera
/// a imagem —, e uma mudança que o baixasse é recusada, mesmo que um dia o
/// `policy.write` passasse a aceitar a linha.
pub const PISOS_DO_QUORUM: &[Piso] = &[Piso {
    operacao: "admin.revoke",
    m_minimo: 2,
    num: 2,
    den: 3,
}];

impl Piso {
    /// Se o quórum `q` está no piso ou acima: M no mínimo, e M/N na fração
    /// mínima, em inteiros — `M·den ≥ N·num`.
    pub const fn cumprido_por(&self, q: Quorum) -> bool {
        q.m >= self.m_minimo && (q.m as u16) * (self.den as u16) >= (q.n as u16) * (self.num as u16)
    }
}

/// O quórum de uma operação: M credenciais distintas de um grupo de N.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quorum {
    pub m: u8,
    pub n: u8,
}

/// O limite de apertos de mão por porta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Apertos {
    pub quantos: u32,
    pub janela_ms: u64,
}

/// O limite de apertos de quem não declara o seu.
pub const APERTOS_PADRAO: Apertos = Apertos {
    quantos: 10,
    janela_ms: 10_000,
};

/// A cota de armazém de um dono: bytes de conteúdo e objetos — arquivos e
/// diretórios. Ver o pacote `armazem`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CotaDoArmazem {
    pub bytes: u64,
    pub objetos: u64,
}

impl CotaDoArmazem {
    /// Nenhuma: o que um papel tem sem a linha `armazem`.
    pub const NENHUMA: CotaDoArmazem = CotaDoArmazem {
        bytes: 0,
        objetos: 0,
    };

    /// Esta cota cabe em `teto`, nas duas medidas.
    pub fn cabe_em(&self, teto: &CotaDoArmazem) -> bool {
        self.bytes <= teto.bytes && self.objetos <= teto.objetos
    }
}

/// O maior número de bytes que uma linha `armazem` dá: 1 TiB. O volume é o
/// limite de verdade; este só impede uma conta absurda.
pub const TETO_DE_BYTES_DO_ARMAZEM: u64 = 1 << 40;
/// O maior número de objetos que uma linha `armazem` dá.
pub const TETO_DE_OBJETOS_DO_ARMAZEM: u64 = 1 << 24;

/// Um papel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Papel {
    pub nome: String,
    /// Os papéis incluídos, como escritos.
    pub inclui: Vec<String>,
    /// As permissões escritas no próprio papel.
    pub diretas: Vec<Permissao>,
    /// Os prefixos a que uma permissão de caminho está limitada.
    pub recursos: BTreeMap<Permissao, Vec<String>>,
    pub taxa: Taxa,
    /// Quantos processos vivos cada titular do papel — uma sessão de agente,
    /// uma de pessoa, o sistema — pode ter ao mesmo tempo.
    pub processos: u32,
    /// As cotas de mensagens de cada titular do papel.
    pub mensagens: crate::mensagens::Cotas,
    /// A cota de armazém de cada dono do papel — cada identidade: um
    /// agente, uma pessoa, o sistema. Sem linha, nenhuma: quem não tem cota
    /// não ocupa nada, mesmo com `fs.write`.
    pub armazem: CotaDoArmazem,
    /// As diretas mais as não sensíveis dos incluídos. Calculadas pela
    /// validação.
    permissoes: BTreeSet<Permissao>,
}

impl Papel {
    fn novo(nome: &str) -> Papel {
        Papel {
            nome: nome.to_string(),
            inclui: Vec::new(),
            diretas: Vec::new(),
            recursos: BTreeMap::new(),
            taxa: TAXA_PADRAO,
            processos: PROCESSOS_PADRAO,
            mensagens: crate::mensagens::COTAS_PADRAO,
            armazem: CotaDoArmazem::NENHUMA,
            permissoes: BTreeSet::new(),
        }
    }

    /// As permissões do papel, já com as dos incluídos.
    pub fn permissoes(&self) -> impl Iterator<Item = Permissao> + '_ {
        self.permissoes.iter().copied()
    }

    /// Se o papel tem a permissão.
    pub fn tem(&self, p: Permissao) -> bool {
        self.permissoes.contains(&p)
    }
}

/// A política inteira.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Politica {
    papeis: Vec<Papel>,
    serial: String,
    local: String,
    apertos: Apertos,
    /// O quórum de cada operação que exige um.
    quoruns: BTreeMap<String, Quorum>,
}

/// O que há de errado numa política.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErroTipo {
    /// Uma linha que não começa com uma palavra conhecida.
    LinhaDesconhecida,
    /// Falta algo na linha, ou sobra.
    Sintaxe,
    /// `*`: não existe permissão para tudo.
    Curinga,
    PermissaoDesconhecida(String),
    PapelRepetido(String),
    PapelDesconhecido(String),
    /// Um papel que, por inclusões, inclui a si mesmo.
    Ciclo(String),
    /// Um nome fora da regra (minúsculas, dígitos, `-`, `_`, `.`).
    NomeInvalido(String),
    Numero(String),
    /// Um `recurso` para uma permissão que o papel não tem.
    RecursoSemPermissao(String),
    /// Um `recurso` para uma permissão cujo recurso não é caminho.
    RecursoNaoECaminho(String),
    /// Um papel com uma permissão de caminho sem o `recurso` que diz o
    /// alcance dela: (papel, permissão).
    RecursoFaltando(String, String),
    CaminhoInvalido(String),
    /// Um destino que não é `papel:<nome>`, com o nome na regra.
    DestinoInvalido(String),
    /// Um destino de rede que não é `tcp:<ipv4>:<porta>` na forma normal —
    /// ver [`crate::endereco`].
    EnderecoInvalido(String),
    /// Falta a linha `serial`.
    SemSerial,
    /// Falta a linha `local`.
    SemLocal,
    /// Uma linha `quorum` para uma operação que não é de quórum.
    OperacaoSemQuorum(String),
    /// Duas linhas `quorum` para a mesma operação.
    QuorumRepetido(String),
    /// Um quórum abaixo do piso da operação: (operação, M, N).
    QuorumAbaixoDoPiso(String, u8, u8),
}

/// Um erro, com a linha onde está. Linha zero: a política como um todo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erro {
    pub linha: usize,
    pub tipo: ErroTipo,
}

impl Erro {
    /// Uma frase, para o log e para a resposta.
    pub fn motivo(&self) -> String {
        let o_que = match &self.tipo {
            ErroTipo::LinhaDesconhecida => "linha desconhecida".to_string(),
            ErroTipo::Sintaxe => "linha incompleta ou com sobra".to_string(),
            ErroTipo::Curinga => "curinga: nao existe permissao para tudo".to_string(),
            ErroTipo::PermissaoDesconhecida(p) => format!("permissao desconhecida `{p}`"),
            ErroTipo::PapelRepetido(p) => format!("papel `{p}` definido duas vezes"),
            ErroTipo::PapelDesconhecido(p) => format!("papel `{p}` nao existe"),
            ErroTipo::Ciclo(p) => format!("o papel `{p}` inclui a si mesmo"),
            ErroTipo::NomeInvalido(n) => format!("nome `{n}` fora da regra"),
            ErroTipo::Numero(n) => format!("numero invalido `{n}`"),
            ErroTipo::RecursoSemPermissao(p) => {
                format!("recurso para `{p}`, que o papel nao tem")
            }
            ErroTipo::RecursoNaoECaminho(p) => {
                format!("`{p}` nao tem alcance: nem caminho, nem destinatario, nem destino de rede")
            }
            ErroTipo::RecursoFaltando(papel, p) => {
                format!("`{papel}` tem `{p}` sem a linha `recurso` que diz o alcance")
            }
            ErroTipo::CaminhoInvalido(c) => format!("caminho invalido `{c}`"),
            ErroTipo::DestinoInvalido(d) => {
                format!("destino invalido `{d}`: so `papel:<nome>`, sem curinga")
            }
            ErroTipo::EnderecoInvalido(d) => format!(
                "destino de rede invalido `{d}`: so `tcp:<ipv4>:<porta>`, na forma normal, sem curinga"
            ),
            ErroTipo::SemSerial => "falta a linha `serial`".to_string(),
            ErroTipo::SemLocal => "falta a linha `local`".to_string(),
            ErroTipo::OperacaoSemQuorum(o) => format!("`{o}` nao e uma operacao de quorum"),
            ErroTipo::QuorumRepetido(o) => format!("quorum de `{o}` definido duas vezes"),
            ErroTipo::QuorumAbaixoDoPiso(o, m, n) => {
                format!("quorum {m} de {n} para `{o}` esta abaixo do piso da operacao")
            }
        };
        if self.linha == 0 {
            o_que
        } else {
            format!("linha {}: {o_que}", self.linha)
        }
    }
}

/// Por que uma mudança de política foi recusada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// A política que resultaria não é válida.
    Invalida(Erro),
    /// A mudança daria a alguém o que o administrador não tem, ou mexeria
    /// num papel protegido.
    Proibida(String),
}

impl Recusa {
    /// O código da auditoria para esta recusa.
    pub fn codigo(&self) -> Codigo {
        match self {
            Recusa::Invalida(_) => Codigo::InvalidArgument,
            Recusa::Proibida(_) => Codigo::DenyPolicy,
        }
    }

    /// Uma frase, para o log e para a resposta.
    pub fn motivo(&self) -> String {
        match self {
            Recusa::Invalida(e) => e.motivo(),
            Recusa::Proibida(m) => m.clone(),
        }
    }
}

/// Um nome de papel aceitável: o mesmo alfabeto dos nomes de agente.
pub fn nome_valido(nome: &str) -> bool {
    !nome.is_empty()
        && nome.len() <= 32
        && nome
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
}

/// Como uma linha entra: lendo o arquivo, um papel repetido é erro; numa
/// mudança em tempo de execução, a linha substitui o que havia.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Modo {
    Arquivo,
    Mudanca,
}

impl Politica {
    /// Lê e valida uma política.
    pub fn ler(texto: &str) -> Result<Politica, Erro> {
        let mut p = Politica {
            papeis: Vec::new(),
            serial: String::new(),
            local: String::new(),
            apertos: APERTOS_PADRAO,
            quoruns: BTreeMap::new(),
        };
        let mut recursos_e_taxas: Vec<(usize, &str)> = Vec::new();
        for (i, linha) in texto.lines().enumerate() {
            let n = i + 1;
            let linha = linha.split('#').next().unwrap_or("").trim();
            if linha.is_empty() {
                continue;
            }
            // Os papéis primeiro, as linhas que os citam depois: um
            // `recurso` antes do `papel` que ele limita é legível e deve
            // valer.
            if linha.starts_with("papel ") || linha == "papel" {
                p.aplicar(n, linha, Modo::Arquivo)?;
            } else {
                recursos_e_taxas.push((n, linha));
            }
        }
        for (n, linha) in recursos_e_taxas {
            p.aplicar(n, linha, Modo::Arquivo)?;
        }
        if p.serial.is_empty() {
            return Err(Erro {
                linha: 0,
                tipo: ErroTipo::SemSerial,
            });
        }
        if p.local.is_empty() {
            return Err(Erro {
                linha: 0,
                tipo: ErroTipo::SemLocal,
            });
        }
        p.validar()?;
        Ok(p)
    }

    /// A política de emergência: o que vale quando a do disco falta ou não
    /// se lê — [`crate::EMERGENCIA`], embutida.
    ///
    /// O `sistema` continua com a autoridade máxima, enumerada como na
    /// política normal, e é o papel da serial e da autoridade local; o
    /// `administrador` continua o teto do que se delega, para recuperar a
    /// política em memória com a prova. Os outros papéis não existem nela: um
    /// agente cujo papel ela não tem é recusado.
    pub fn emergencia() -> Politica {
        // O texto é deste pacote, e um teste confere que ele vale. Uma
        // política embutida inválida é erro de quem a escreveu, e não um
        // estado do sistema.
        Politica::ler(crate::EMERGENCIA).expect("a politica de emergencia embutida vale")
    }

    fn papel_mut(&mut self, nome: &str) -> Option<&mut Papel> {
        self.papeis.iter_mut().find(|p| p.nome == nome)
    }

    /// Um papel, pelo nome.
    pub fn papel(&self, nome: &str) -> Option<&Papel> {
        self.papeis.iter().find(|p| p.nome == nome)
    }

    /// Todos os papéis, na ordem do arquivo.
    pub fn papeis(&self) -> &[Papel] {
        &self.papeis
    }

    /// O papel da serial.
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// O papel da autoridade local: os processos do sistema.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// O limite de apertos por porta.
    pub fn apertos(&self) -> Apertos {
        self.apertos
    }

    /// O quórum de `operacao`, se a política o define. Sem a linha, a
    /// operação não existe: nada a substitui por uma credencial só.
    pub fn quorum(&self, operacao: &str) -> Option<Quorum> {
        self.quoruns.get(operacao).copied()
    }

    /// Aplica uma linha já sem comentário.
    fn aplicar(&mut self, n: usize, linha: &str, modo: Modo) -> Result<(), Erro> {
        let erro = |tipo| Erro { linha: n, tipo };
        let mut partes = linha.split_ascii_whitespace();
        let palavra = partes.next().unwrap_or("");
        match palavra {
            "papel" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                if !nome_valido(nome) {
                    return Err(erro(ErroTipo::NomeInvalido(nome.to_string())));
                }
                let mut papel = Papel::novo(nome);
                for item in partes {
                    if item.contains('*') {
                        return Err(erro(ErroTipo::Curinga));
                    }
                    if let Some(incluido) = item.strip_prefix('@') {
                        if !nome_valido(incluido) {
                            return Err(erro(ErroTipo::NomeInvalido(incluido.to_string())));
                        }
                        papel.inclui.push(incluido.to_string());
                    } else {
                        let p = Permissao::de_nome(item)
                            .ok_or(erro(ErroTipo::PermissaoDesconhecida(item.to_string())))?;
                        if !papel.diretas.contains(&p) {
                            papel.diretas.push(p);
                        }
                    }
                }
                match self.papel_mut(nome) {
                    Some(existente) if modo == Modo::Mudanca => {
                        // A definição muda; o que outras linhas disseram
                        // dele — recursos e taxa — fica.
                        existente.inclui = papel.inclui;
                        existente.diretas = papel.diretas;
                    }
                    Some(_) => return Err(erro(ErroTipo::PapelRepetido(nome.to_string()))),
                    None => self.papeis.push(papel),
                }
            }
            "recurso" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let p = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let p = Permissao::de_nome(p)
                    .ok_or(erro(ErroTipo::PermissaoDesconhecida(p.to_string())))?;
                if !p.tem_alcance() {
                    return Err(erro(ErroTipo::RecursoNaoECaminho(p.nome().to_string())));
                }
                let mut prefixos = Vec::new();
                for c in partes {
                    if p.recurso_e_destino() {
                        // Um papel pelo nome, e só: nada de curinga, nada de
                        // identidade solta. Se o papel existe é a decisão que
                        // confere, com a política em vigor — a de emergência
                        // não tem o operador, e o alcance do `sistema` é o
                        // mesmo texto nas duas.
                        let nome = c
                            .strip_prefix(PREFIXO_DE_DESTINO)
                            .filter(|n| nome_valido(n))
                            .ok_or(erro(ErroTipo::DestinoInvalido(c.to_string())))?;
                        prefixos.push(alloc::format!("{PREFIXO_DE_DESTINO}{nome}"));
                    } else if p.recurso_e_endereco() {
                        // Um destino inteiro, na forma normal — e só ela:
                        // a linha que escreve `tcp:010.0.2.1:7` é recusada,
                        // e não lida como outra coisa.
                        let normal = crate::endereco::normalizar(c)
                            .filter(|n| n == c)
                            .ok_or(erro(ErroTipo::EnderecoInvalido(c.to_string())))?;
                        if !prefixos.contains(&normal) {
                            prefixos.push(normal);
                        }
                    } else {
                        let normal = caminho::normalizar(c)
                            .ok_or(erro(ErroTipo::CaminhoInvalido(c.to_string())))?;
                        prefixos.push(normal);
                    }
                }
                if prefixos.is_empty() {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                let papel = self
                    .papel_mut(nome)
                    .ok_or(erro(ErroTipo::PapelDesconhecido(nome.to_string())))?;
                papel.recursos.insert(p, prefixos);
            }
            "taxa" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let por_segundo = numero(partes.next(), n)?;
                let rajada = numero(partes.next(), n)?;
                if partes.next().is_some() || por_segundo == 0 || rajada == 0 {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                let papel = self
                    .papel_mut(nome)
                    .ok_or(erro(ErroTipo::PapelDesconhecido(nome.to_string())))?;
                papel.taxa = Taxa {
                    por_segundo,
                    rajada,
                };
            }
            "processos" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let quantos = numero(partes.next(), n)?;
                if partes.next().is_some() || quantos == 0 || quantos > MAIS_PROCESSOS {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                let papel = self
                    .papel_mut(nome)
                    .ok_or(erro(ErroTipo::PapelDesconhecido(nome.to_string())))?;
                papel.processos = quantos;
            }
            "mensagens" => {
                use crate::mensagens::{Cotas, TETO_POR_CAIXA, TETO_POR_REMETENTE};
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let por_remetente = numero(partes.next(), n)? as usize;
                let por_caixa = numero(partes.next(), n)? as usize;
                // Zero não é cota: um papel que não deve mandar não tem
                // `message.send`. E o teto é da tabela — a memória das
                // mensagens —, que nenhuma política alarga.
                if partes.next().is_some()
                    || !(1..=TETO_POR_REMETENTE).contains(&por_remetente)
                    || !(1..=TETO_POR_CAIXA).contains(&por_caixa)
                {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                let papel = self
                    .papel_mut(nome)
                    .ok_or(erro(ErroTipo::PapelDesconhecido(nome.to_string())))?;
                papel.mensagens = Cotas {
                    por_remetente,
                    por_caixa,
                };
            }
            "armazem" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let bytes = numero_grande(partes.next(), n)?;
                let objetos = numero_grande(partes.next(), n)?;
                // Zero não é cota: um papel que não deve guardar nada fica
                // sem a linha. E o teto é desta política, que nenhuma linha
                // alarga.
                if partes.next().is_some()
                    || !(1..=TETO_DE_BYTES_DO_ARMAZEM).contains(&bytes)
                    || !(1..=TETO_DE_OBJETOS_DO_ARMAZEM).contains(&objetos)
                {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                let papel = self
                    .papel_mut(nome)
                    .ok_or(erro(ErroTipo::PapelDesconhecido(nome.to_string())))?;
                papel.armazem = CotaDoArmazem { bytes, objetos };
            }
            "quorum" => {
                let operacao = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                let m = numero(partes.next(), n)?;
                let total = numero(partes.next(), n)?;
                // Um quórum de um é a prova de uma credencial só, que já
                // existe; o de zero não é quórum. E o grupo tem teto.
                if partes.next().is_some() || m < 2 || m > total || total > u32::from(MAIOR_GRUPO) {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                if !OPERACOES_DE_QUORUM.contains(&operacao) {
                    return Err(erro(ErroTipo::OperacaoSemQuorum(operacao.to_string())));
                }
                let quorum = Quorum {
                    m: m as u8,
                    n: total as u8,
                };
                if self.quoruns.insert(operacao.to_string(), quorum).is_some() {
                    return Err(erro(ErroTipo::QuorumRepetido(operacao.to_string())));
                }
            }
            "apertos" => {
                let quantos = numero(partes.next(), n)?;
                let janela = numero(partes.next(), n)?;
                if partes.next().is_some() || quantos == 0 || janela == 0 {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                self.apertos = Apertos {
                    quantos,
                    janela_ms: u64::from(janela),
                };
            }
            "serial" | "local" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                if partes.next().is_some() {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                if palavra == "serial" {
                    self.serial = nome.to_string();
                } else {
                    self.local = nome.to_string();
                }
            }
            _ => return Err(erro(ErroTipo::LinhaDesconhecida)),
        }
        Ok(())
    }

    /// Confere o que só se confere com tudo lido, e calcula as permissões.
    fn validar(&mut self) -> Result<(), Erro> {
        let geral = |tipo| Erro { linha: 0, tipo };
        for papel in [&self.serial, &self.local] {
            if self.papel(papel).is_none() {
                return Err(geral(ErroTipo::PapelDesconhecido(papel.clone())));
            }
        }
        for papel in &self.papeis {
            for incluido in &papel.inclui {
                if self.papel(incluido).is_none() {
                    return Err(geral(ErroTipo::PapelDesconhecido(incluido.clone())));
                }
            }
        }
        let mut expandidas = Vec::new();
        for papel in &self.papeis {
            let mut caminho = Vec::new();
            expandidas.push(self.expandir(&papel.nome, &mut caminho)?);
        }
        for (papel, permissoes) in self.papeis.iter_mut().zip(expandidas) {
            papel.permissoes = permissoes;
        }
        for papel in &self.papeis {
            for p in papel.recursos.keys() {
                if !papel.tem(*p) {
                    return Err(geral(ErroTipo::RecursoSemPermissao(p.nome().to_string())));
                }
            }
            // E o contrário: cada permissão de caminho tem o alcance
            // escrito. Também a que veio por inclusão — o alcance é de cada
            // papel, e não se herda.
            for p in papel.permissoes() {
                if p.tem_alcance() && !papel.recursos.contains_key(&p) {
                    return Err(geral(ErroTipo::RecursoFaltando(
                        papel.nome.clone(),
                        p.nome().to_string(),
                    )));
                }
            }
        }
        // O piso do quórum de cada operação crítica: ver `PISOS_DO_QUORUM`.
        for piso in PISOS_DO_QUORUM {
            if let Some(q) = self.quoruns.get(piso.operacao)
                && !piso.cumprido_por(*q)
            {
                return Err(geral(ErroTipo::QuorumAbaixoDoPiso(
                    piso.operacao.to_string(),
                    q.m,
                    q.n,
                )));
            }
        }
        Ok(())
    }

    /// As permissões de um papel, seguindo as inclusões. `caminho` é a
    /// pilha da descida, para achar ciclo.
    fn expandir(&self, nome: &str, caminho: &mut Vec<String>) -> Result<BTreeSet<Permissao>, Erro> {
        if caminho.iter().any(|c| c == nome) {
            return Err(Erro {
                linha: 0,
                tipo: ErroTipo::Ciclo(nome.to_string()),
            });
        }
        let papel = self.papel(nome).ok_or(Erro {
            linha: 0,
            tipo: ErroTipo::PapelDesconhecido(nome.to_string()),
        })?;
        caminho.push(nome.to_string());
        let mut todas: BTreeSet<Permissao> = papel.diretas.iter().copied().collect();
        for incluido in &papel.inclui {
            // Só as não sensíveis atravessam a inclusão.
            todas.extend(
                self.expandir(incluido, caminho)?
                    .into_iter()
                    .filter(|p| !p.sensivel()),
            );
        }
        caminho.pop();
        Ok(todas)
    }

    /// A decisão: este papel, esta permissão, este recurso.
    ///
    /// `recurso` é o caminho, para as permissões de caminho; para as outras,
    /// não é olhado. Sem papel, ou com um que a política não tem:
    /// `DENY_ROLE`. Sem a permissão: `DENY_PERMISSION`. Com o recurso fora
    /// do alcance — ou ausente, ou que não se normaliza, ou sem alcance
    /// escrito —: `DENY_RESOURCE`. Não há papel que pule esta conta: o
    /// `sistema` passa por ela como os outros, com o que ele enumera.
    pub fn decidir(&self, papel: Option<&str>, p: Permissao, recurso: Option<&str>) -> Codigo {
        let Some(papel) = papel.and_then(|n| self.papel(n)) else {
            return Codigo::DenyRole;
        };
        if !papel.tem(p) {
            return Codigo::DenyPermission;
        }
        if p.recurso_e_caminho() {
            // A validação exige o alcance; sem ele, fechado — nunca "tudo".
            let Some(prefixos) = papel.recursos.get(&p) else {
                return Codigo::DenyResource;
            };
            let Some(normal) = recurso.and_then(caminho::normalizar) else {
                return Codigo::DenyResource;
            };
            if !prefixos.iter().any(|pre| caminho::dentro_de(&normal, pre)) {
                return Codigo::DenyResource;
            }
        }
        if p.recurso_e_destino() {
            // O papel do destinatário, igual a um dos enumerados — e um
            // papel que esta política tem. Sem destinatário resolvido, ou
            // fora da lista: fechado.
            let Some(alcance) = papel.recursos.get(&p) else {
                return Codigo::DenyResource;
            };
            let Some(alvo) = recurso else {
                return Codigo::DenyResource;
            };
            let existe = alvo
                .strip_prefix(PREFIXO_DE_DESTINO)
                .is_some_and(|nome| self.papel(nome).is_some());
            if !existe || !alcance.iter().any(|a| a == alvo) {
                return Codigo::DenyResource;
            }
        }
        if p.recurso_e_endereco() {
            // O destino de rede, na forma normal, igual a um dos
            // enumerados. Sem destino, ou um que não se lê: fechado.
            let Some(alcance) = papel.recursos.get(&p) else {
                return Codigo::DenyResource;
            };
            let Some(normal) = recurso.and_then(crate::endereco::normalizar) else {
                return Codigo::DenyResource;
            };
            if !alcance.contains(&normal) {
                return Codigo::DenyResource;
            }
        }
        Codigo::Allow
    }

    /// Só o papel local — o do sistema — e o próprio papel de administrador
    /// alcançam um papel de administrador com `message.send`.
    ///
    /// É um invariante da política, e não uma preferência da imagem: um
    /// operador ou um observador que alcançasse o administrador seria um
    /// canal para levar quem tem o papel mais forte a agir. O kernel o
    /// confere no boot — uma política que o viole não vigora, e vale a de
    /// emergência —, o `xtask` antes de pôr a política na imagem, e
    /// `policy.write` em cada mudança.
    ///
    /// `administradores` são os papéis a proteger: o `administrador`, e os
    /// das chaves de administrador do registro.
    pub fn conferir_alcance_aos_administradores(
        &self,
        administradores: &[&str],
    ) -> Result<(), String> {
        for admin in administradores {
            let alvo = format!("{PREFIXO_DE_DESTINO}{admin}");
            for papel in &self.papeis {
                if papel.nome == self.local || papel.nome == *admin {
                    continue;
                }
                let alcanca = papel
                    .recursos
                    .get(&Permissao::MessageSend)
                    .is_some_and(|r| r.contains(&alvo));
                if alcanca {
                    return Err(format!(
                        "o papel `{}` alcanca `{alvo}`: so o sistema e o proprio administrador o \
                         alcancam",
                        papel.nome
                    ));
                }
            }
        }
        Ok(())
    }

    /// Nenhum teto é exercido pela serial nem pela autoridade local.
    ///
    /// Um teto — o papel de um administrador — diz o que se delega, e não o
    /// que se exerce: a serial e a autoridade local decidem pelo papel delas
    /// em cada pedido, e um teto ali seria exercido sem linha nenhuma o
    /// conceder. O kernel confere no boot, o `xtask` antes de pôr a política
    /// na imagem. `tetos` são os papéis dos administradores.
    pub fn conferir_tetos(&self, tetos: &[&str]) -> Result<(), String> {
        for (linha, papel) in [("serial", &self.serial), ("local", &self.local)] {
            if tetos.contains(&papel.as_str()) {
                return Err(format!(
                    "a linha `{linha}` da o papel `{papel}`, que e o teto de um administrador: um teto delega, nao se exerce"
                ));
            }
        }
        Ok(())
    }

    /// O papel `papel` cabe inteiro no papel `teto`: cada permissão dele o
    /// teto tem, e com recurso no mínimo tão limitado quanto o do teto.
    ///
    /// É a regra do registro e da atribuição: um administrador concede
    /// papéis que cabem no seu. Sem ela, quem tem `agent.register` poderia
    /// registrar uma chave sua com um papel maior e usar o que não tinha.
    pub fn cabe_em(&self, papel: &str, teto: &str) -> Result<(), Recusa> {
        let (Some(a), Some(t)) = (self.papel(papel), self.papel(teto)) else {
            return Err(Recusa::Proibida(format!(
                "papel `{papel}` ou `{teto}` nao existe"
            )));
        };
        if !a.armazem.cabe_em(&t.armazem) {
            return Err(Recusa::Proibida(format!(
                "`{papel}` tem uma cota de armazem maior que a do administrador"
            )));
        }
        for p in a.permissoes() {
            if !t.tem(p) {
                return Err(Recusa::Proibida(format!(
                    "`{papel}` tem `{}`, que o administrador nao tem",
                    p.nome()
                )));
            }
            if !recurso_contido(p, a.recursos.get(&p), t.recursos.get(&p)) {
                return Err(Recusa::Proibida(format!(
                    "`{papel}` alcanca com `{}` caminhos fora do alcance do administrador",
                    p.nome()
                )));
            }
        }
        Ok(())
    }

    /// A política com uma linha de `policy.write` aplicada.
    ///
    /// Só `papel`, `recurso` e `taxa`: a serial muda por `policy.assign`, e
    /// o limite de apertos só pela imagem. A política que resulta é validada
    /// inteira, como o arquivo; e cada papel que **muda** — o da linha, e os
    /// que o incluem — passa por duas regras:
    ///
    /// - não pode ser `teto`, o papel de quem pede, nem um dos `protegidos` —
    ///   os papéis de administradores e o da sessão de onde o pedido vem:
    ///   ninguém muda o próprio papel, nem remove a restrição de que precisa
    ///   para fazer o que faz;
    /// - o que ele **ganha** — permissões novas, recursos alargados — tem de
    ///   caber no teto: ninguém concede o que não tem.
    pub fn com_linha(
        &self,
        linha: &str,
        teto: &str,
        protegidos: &[&str],
    ) -> Result<Politica, Recusa> {
        let linha = linha.split('#').next().unwrap_or("").trim();
        let palavra = linha.split_ascii_whitespace().next().unwrap_or("");
        if !matches!(
            palavra,
            "papel" | "recurso" | "taxa" | "processos" | "mensagens" | "armazem"
        ) {
            return Err(Recusa::Proibida(
                "policy.write muda papel, recurso, taxa, processos, mensagens ou armazem; a serial \
                 muda por policy.assign, e o papel local e os apertos so pela imagem"
                    .to_string(),
            ));
        }
        // O alvo da linha primeiro: mexer no próprio papel, ou no de outro
        // administrador, é recusado pelo que é — e não por um efeito
        // colateral que a validação pegasse depois, com outro motivo.
        if let Some(alvo) = linha.split_ascii_whitespace().nth(1)
            && (alvo == teto || protegidos.contains(&alvo))
        {
            return Err(Recusa::Proibida(format!(
                "o papel `{alvo}` e protegido (de um administrador, ou da sessao que pede) e nao muda em tempo de execucao"
            )));
        }
        let mut nova = self.clone();
        nova.aplicar(1, linha, Modo::Mudanca)
            .map_err(Recusa::Invalida)?;
        nova.validar().map_err(Recusa::Invalida)?;
        // O alcance ao administrador está no teto — é o que torna o do
        // sistema e o dele representáveis —, e ainda assim não se dá a mais
        // ninguém: o invariante vale para a política que resultaria.
        nova.conferir_alcance_aos_administradores(&[teto])
            .map_err(Recusa::Proibida)?;
        let t = self.papel(teto).ok_or(Recusa::Proibida(format!(
            "o papel `{teto}` do administrador nao existe"
        )))?;
        for depois in &nova.papeis {
            let antes = self.papel(&depois.nome);
            if antes == Some(depois) {
                continue;
            }
            if depois.nome == teto || protegidos.contains(&depois.nome.as_str()) {
                return Err(Recusa::Proibida(format!(
                    "a mudanca alteraria o papel `{}`, que e protegido",
                    depois.nome
                )));
            }
            // A cota de armazém que cresce cabe na do teto: ninguém concede
            // mais espaço do que o dele.
            let cresceu = antes.is_none_or(|a| !depois.armazem.cabe_em(&a.armazem));
            if cresceu && !depois.armazem.cabe_em(&t.armazem) {
                return Err(Recusa::Proibida(format!(
                    "a mudanca daria a `{}` uma cota de armazem maior que a do administrador",
                    depois.nome
                )));
            }
            for p in depois.permissoes() {
                let ja_tinha = antes.is_some_and(|a| a.tem(p));
                let alargou = antes.is_some_and(|a| {
                    a.tem(p) && !recurso_contido(p, depois.recursos.get(&p), a.recursos.get(&p))
                });
                if !ja_tinha && !t.tem(p) {
                    return Err(Recusa::Proibida(format!(
                        "a mudanca daria `{}` a `{}`, e o administrador nao a tem",
                        p.nome(),
                        depois.nome
                    )));
                }
                if (!ja_tinha || alargou)
                    && !recurso_contido(p, depois.recursos.get(&p), t.recursos.get(&p))
                {
                    return Err(Recusa::Proibida(format!(
                        "a mudanca alargaria `{}` de `{}` alem do alcance do administrador",
                        p.nome(),
                        depois.nome
                    )));
                }
            }
        }
        Ok(nova)
    }

    /// As cotas de um envio: a de remetente do papel de quem manda, e a de
    /// caixa do papel de quem recebe. Um papel que a política não tem não
    /// tem cota nenhuma — [`crate::mensagens::SEM_COTA`] —: quem não tem
    /// papel não guarda mensagem.
    pub fn cotas_de_mensagens(
        &self,
        remetente: Option<&str>,
        destinatario: Option<&str>,
    ) -> crate::mensagens::Cotas {
        let cotas = |nome: Option<&str>| {
            nome.and_then(|n| self.papel(n))
                .map_or(crate::mensagens::SEM_COTA, |p| p.mensagens)
        };
        crate::mensagens::Cotas {
            por_remetente: cotas(remetente).por_remetente,
            por_caixa: cotas(destinatario).por_caixa,
        }
    }

    /// A política como texto que [`Politica::ler`] lê de volta igual.
    ///
    /// # Para que serve
    ///
    /// Para a persistência: uma política mudada em tempo de execução vai
    /// inteira para o journal, e não como a linha que a mudou. Reaplicar a
    /// linha no boot dependeria de a política da imagem continuar a mesma e
    /// de as regras de quem pode mudar o quê darem o mesmo resultado — o
    /// texto inteiro não depende de nada, e passa de novo pela validação
    /// inteira ao ser lido, piso do quórum incluído.
    ///
    /// Uma linha por fato, na ordem em que o leitor os aceita: os papéis,
    /// depois o que cada um diz dos papéis, e por fim o que é da política.
    /// Tudo é escrito, mesmo o que tem o valor padrão: o texto descreve a
    /// política sem depender de quais são os padrões de quem o ler.
    pub fn texto(&self) -> String {
        use core::fmt::Write;
        let mut t = String::new();
        for papel in &self.papeis {
            let _ = write!(t, "papel {}", papel.nome);
            for incluido in &papel.inclui {
                let _ = write!(t, " @{incluido}");
            }
            for p in &papel.diretas {
                let _ = write!(t, " {}", p.nome());
            }
            t.push('\n');
        }
        for papel in &self.papeis {
            for (p, alcance) in &papel.recursos {
                let _ = write!(t, "recurso {} {}", papel.nome, p.nome());
                for a in alcance {
                    let _ = write!(t, " {a}");
                }
                t.push('\n');
            }
            let _ = writeln!(
                t,
                "taxa {} {} {}",
                papel.nome, papel.taxa.por_segundo, papel.taxa.rajada
            );
            let _ = writeln!(t, "processos {} {}", papel.nome, papel.processos);
            let _ = writeln!(
                t,
                "mensagens {} {} {}",
                papel.nome, papel.mensagens.por_remetente, papel.mensagens.por_caixa
            );
            if papel.armazem != CotaDoArmazem::NENHUMA {
                let _ = writeln!(
                    t,
                    "armazem {} {} {}",
                    papel.nome, papel.armazem.bytes, papel.armazem.objetos
                );
            }
        }
        let _ = writeln!(t, "serial {}", self.serial);
        let _ = writeln!(t, "local {}", self.local);
        let _ = writeln!(
            t,
            "apertos {} {}",
            self.apertos.quantos, self.apertos.janela_ms
        );
        for (operacao, q) in &self.quoruns {
            let _ = writeln!(t, "quorum {operacao} {} {}", q.m, q.n);
        }
        t
    }

    /// A política com outro papel para a serial.
    pub fn com_serial(&self, papel: &str) -> Result<Politica, Recusa> {
        if self.papel(papel).is_none() {
            return Err(Recusa::Invalida(Erro {
                linha: 0,
                tipo: ErroTipo::PapelDesconhecido(papel.to_string()),
            }));
        }
        let mut nova = self.clone();
        nova.serial = papel.to_string();
        Ok(nova)
    }
}

/// O alcance `a` está contido no alcance `b`. `None` é alcance nenhum — o de
/// uma permissão que não é de caminho, ou o de um papel sem a permissão: está
/// contido em qualquer um, e não contém nada além de outro `None`.
///
/// Um caminho está contido no prefixo que o contém; um destinatário, só no
/// mesmo destinatário — papéis não têm hierarquia de nome —; e um destino
/// de rede, só no mesmo destino: não há faixa que contenha outra.
fn recurso_contido(p: Permissao, a: Option<&Vec<String>>, b: Option<&Vec<String>>) -> bool {
    match (a, b) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) if p.recurso_e_destino() || p.recurso_e_endereco() => {
            a.iter().all(|pa| b.contains(pa))
        }
        (Some(a), Some(b)) => a
            .iter()
            .all(|pa| b.iter().any(|pb| caminho::dentro_de(pa, pb))),
    }
}

/// Como um destino se escreve no alcance de `message.send`, e como a
/// decisão o recebe: o papel do destinatário.
pub const PREFIXO_DE_DESTINO: &str = "papel:";

/// Um número de 64 bits, para as cotas de armazém.
fn numero_grande(texto: Option<&str>, n: usize) -> Result<u64, Erro> {
    texto.and_then(|t| t.parse::<u64>().ok()).ok_or(Erro {
        linha: n,
        tipo: ErroTipo::Sintaxe,
    })
}

fn numero(texto: Option<&str>, n: usize) -> Result<u32, Erro> {
    let texto = texto.ok_or(Erro {
        linha: n,
        tipo: ErroTipo::Sintaxe,
    })?;
    texto.parse().map_err(|_| Erro {
        linha: n,
        tipo: ErroTipo::Numero(texto.to_string()),
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O texto de uma política se lê de volta na mesma política: as duas
    /// embutidas, e as que saem delas por cada tipo de mudança em tempo de
    /// execução. É o que a persistência grava, e o que o boot relê.
    #[test]
    fn o_texto_volta_igual() {
        let padrao = Politica::ler(crate::PADRAO).unwrap();
        let mut politicas = alloc::vec![padrao.clone(), Politica::emergencia()];
        for linha in [
            "papel observador agent.read system.read",
            "recurso operador fs.read /dados",
            "taxa observador 7 21",
            "processos observador 3",
            "mensagens observador 3 9",
        ] {
            politicas.push(padrao.com_linha(linha, "administrador", &[]).unwrap());
        }
        politicas.push(padrao.com_serial("administrador").unwrap());
        for p in politicas {
            let texto = p.texto();
            let relida =
                Politica::ler(&texto).unwrap_or_else(|e| panic!("{}\n---\n{texto}", e.motivo()));
            assert_eq!(relida, p, "\n{texto}");
            // E o texto do texto é o mesmo texto: nada se perde nem se
            // acrescenta numa segunda volta.
            assert_eq!(relida.texto(), texto);
        }
    }

    /// O texto passa pela validação inteira de novo: um quórum abaixo do
    /// piso escrito à mão no texto gravado é recusado na leitura.
    #[test]
    fn o_texto_gravado_passa_pelo_piso() {
        let texto = Politica::ler(crate::PADRAO).unwrap().texto();
        assert!(texto.contains("quorum admin.revoke 2 3\n"));
        let rebaixado = texto.replace("quorum admin.revoke 2 3", "quorum admin.revoke 2 4");
        assert!(Politica::ler(&rebaixado).is_err());
    }

    /// A cota de processos: a da linha, a padrão sem ela, e a linha fora da
    /// faixa recusada; e `policy.write` a muda.
    #[test]
    fn a_cota_de_processos() {
        let p = Politica::ler(crate::PADRAO).unwrap();
        assert_eq!(p.papel("sistema").unwrap().processos, 32);
        assert_eq!(p.papel("observador").unwrap().processos, 2);
        let sem = crate::PADRAO.replace("processos observador 2\n", "");
        assert_eq!(
            Politica::ler(&sem)
                .unwrap()
                .papel("observador")
                .unwrap()
                .processos,
            PROCESSOS_PADRAO
        );
        for ruim in [
            "processos observador 0",
            "processos observador 65",
            "processos fantasma 2",
        ] {
            let texto = alloc::format!("{}\n{ruim}\n", crate::PADRAO);
            assert!(Politica::ler(&texto).is_err(), "{ruim}");
        }
        let nova = p
            .com_linha("processos observador 3", "administrador", &[])
            .unwrap();
        assert_eq!(nova.papel("observador").unwrap().processos, 3);
    }

    /// O quórum: a linha, as duas políticas embutidas com o 2 de 3 do
    /// `admin.revoke`, a faixa, a operação que não é de quórum e a repetida
    /// recusadas — e o `policy.write` não o muda: baixar o M seria uma
    /// credencial só desfazendo o quórum.
    #[test]
    fn o_quorum() {
        for p in [
            Politica::ler(crate::PADRAO).unwrap(),
            Politica::emergencia(),
        ] {
            assert_eq!(p.quorum("admin.revoke"), Some(Quorum { m: 2, n: 3 }));
            assert_eq!(p.quorum("agent.revoke"), None);
            assert_eq!(
                p.decidir(Some("administrador"), Permissao::AdminRevoke, None),
                Codigo::Allow
            );
            for papel in ["sistema", "operador", "observador"] {
                assert_ne!(
                    p.decidir(Some(papel), Permissao::AdminRevoke, None),
                    Codigo::Allow,
                    "{papel}"
                );
            }
        }
        let sem = crate::PADRAO.replace("quorum admin.revoke 2 3\n", "");
        assert_eq!(Politica::ler(&sem).unwrap().quorum("admin.revoke"), None);
        for ruim in [
            "quorum admin.revoke 1 3",
            "quorum admin.revoke 0 3",
            "quorum admin.revoke 4 3",
            "quorum admin.revoke 2 17",
            "quorum admin.revoke 2",
            "quorum admin.revoke 2 3 4",
            "quorum agent.revoke 2 3",
            "quorum admin.revoke 3 3",
        ] {
            let texto = alloc::format!("{sem}\n{ruim}\n");
            let ok = ruim == "quorum admin.revoke 3 3";
            assert_eq!(Politica::ler(&texto).is_ok(), ok, "{ruim}");
        }
        // Repetida, mesmo igual.
        let dupla = alloc::format!("{}\nquorum admin.revoke 2 3\n", crate::PADRAO);
        assert!(Politica::ler(&dupla).is_err());
        let p = Politica::ler(crate::PADRAO).unwrap();
        for linha in ["quorum admin.revoke 1 3", "quorum admin.revoke 3 3"] {
            assert!(p.com_linha(linha, "administrador", &[]).is_err(), "{linha}");
        }
        // Nem a linha que valeria no arquivo: o `policy.write` não escreve
        // quórum nenhum, nem numa política que não o tem.
        let sem_quorum = Politica::ler(&sem).unwrap();
        assert!(matches!(
            sem_quorum.com_linha("quorum admin.revoke 2 3", "administrador", &[]),
            Err(Recusa::Proibida(_))
        ));
    }

    /// O piso do quórum de `admin.revoke`: 2 de 3, em proporção. Abaixo
    /// dele, nenhuma política vale — nem do arquivo, nem a que resultaria de
    /// um `policy.write` —; no piso e acima, sim.
    #[test]
    fn o_piso_do_quorum() {
        let sem = crate::PADRAO.replace("quorum admin.revoke 2 3\n", "");
        let com = |linha: &str| Politica::ler(&alloc::format!("{sem}\n{linha}\n"));
        for (m, n) in [(2, 4), (3, 5), (4, 7), (2, 5), (5, 8)] {
            let linha = alloc::format!("quorum admin.revoke {m} {n}");
            assert!(
                matches!(
                    com(&linha),
                    Err(Erro {
                        tipo: ErroTipo::QuorumAbaixoDoPiso(_, _, _),
                        ..
                    })
                ),
                "{linha} passou abaixo do piso"
            );
        }
        for (m, n) in [(2, 3), (3, 3), (3, 4), (4, 5), (4, 6), (11, 16)] {
            let linha = alloc::format!("quorum admin.revoke {m} {n}");
            assert!(com(&linha).is_ok(), "{linha} no piso foi recusada");
        }
        // As duas embutidas estão no piso.
        let piso = PISOS_DO_QUORUM[0];
        for p in [
            Politica::ler(crate::PADRAO).unwrap(),
            Politica::emergencia(),
        ] {
            assert!(piso.cumprido_por(p.quorum("admin.revoke").unwrap()));
        }
    }

    /// Nenhum `policy.write` mexe no quórum de `admin.revoke`: nem para
    /// baixar — 1 de 3, 2 de 4, 2 de 5 —, nem para manter, nem para subir, e
    /// nem numa política que ainda não tenha a linha. O quórum é da imagem.
    /// A cota de armazém: lida, escrita de volta igual, com tetos, e sem
    /// linha é nenhuma. Um `policy.write` que a aumenta cabe no teto de
    /// quem delega; uma atribuição de papel também.
    #[test]
    fn a_cota_do_armazem() {
        let p = Politica::ler(crate::PADRAO).unwrap();
        assert_eq!(
            p.papel("operador").unwrap().armazem,
            CotaDoArmazem {
                bytes: 16 * 1024 * 1024,
                objetos: 4096
            }
        );
        assert_eq!(
            p.papel("observador").unwrap().armazem,
            CotaDoArmazem::NENHUMA
        );
        assert_eq!(Politica::ler(&p.texto()).unwrap(), p);
        for ruim in [
            "armazem operador 0 5",
            "armazem operador 5 0",
            "armazem operador 1099511627777 5",
            "armazem operador 5 16777217",
            "armazem operador 5",
            "armazem operador 5 5 5",
            "armazem operador -1 5",
            "armazem fantasma 5 5",
        ] {
            assert!(p.com_linha(ruim, "administrador", &[]).is_err(), "{ruim}");
        }
        // Dentro do teto do administrador: muda.
        let nova = p
            .com_linha("armazem operador 1000 10", "administrador", &[])
            .unwrap();
        assert_eq!(
            nova.papel("operador").unwrap().armazem,
            CotaDoArmazem {
                bytes: 1000,
                objetos: 10
            }
        );
        // Além do teto: não — nem pelos bytes, nem pelos objetos.
        assert!(matches!(
            p.com_linha("armazem operador 67108865 10", "administrador", &[]),
            Err(Recusa::Proibida(_))
        ));
        assert!(matches!(
            p.com_linha("armazem operador 10 16385", "administrador", &[]),
            Err(Recusa::Proibida(_))
        ));
        // Diminuir passa sempre que o papel não é protegido.
        assert!(
            p.com_linha("armazem operador 1 1", "administrador", &[])
                .is_ok()
        );
        // Um papel com cota maior que o teto não se atribui por ele.
        let grande = p
            .com_linha("armazem observador 1 1", "administrador", &[])
            .unwrap();
        assert!(grande.cabe_em("observador", "administrador").is_ok());
        let alem = Politica::ler(&alloc::format!(
            "{}armazem observador 67108865 1\n",
            crate::PADRAO
        ))
        .unwrap();
        assert!(alem.cabe_em("observador", "administrador").is_err());
    }

    #[test]
    fn o_policy_write_nao_baixa_o_quorum() {
        let p = Politica::ler(crate::PADRAO).unwrap();
        let sem = Politica::ler(&crate::PADRAO.replace("quorum admin.revoke 2 3\n", "")).unwrap();
        for linha in [
            "quorum admin.revoke 1 3",
            "quorum admin.revoke 2 4",
            "quorum admin.revoke 2 5",
            "quorum admin.revoke 1 1",
            "quorum admin.revoke 2 3",
            "quorum admin.revoke 3 3",
        ] {
            for alvo in [&p, &sem] {
                assert!(
                    matches!(
                        alvo.com_linha(linha, "administrador", &[]),
                        Err(Recusa::Proibida(_))
                    ),
                    "policy.write aceitou `{linha}`"
                );
            }
        }
        // E o quórum de antes continua o que era.
        assert_eq!(p.quorum("admin.revoke"), Some(Quorum { m: 2, n: 3 }));
        // Nem por uma linha que não é de quórum: nenhuma outra palavra muda
        // o quórum de uma política válida.
        for linha in [
            "papel operador @observador ui.act",
            "taxa operador 50 100",
            "processos operador 4",
            "mensagens operador 2 2",
        ] {
            if let Ok(nova) = p.com_linha(linha, "administrador", &[]) {
                assert_eq!(
                    nova.quorum("admin.revoke"),
                    Some(Quorum { m: 2, n: 3 }),
                    "{linha}"
                );
            }
        }
    }

    /// As cotas de mensagens: as da linha, as padrão sem ela, cada uma do
    /// papel certo — a de remetente de quem manda, a de caixa de quem
    /// recebe —, e nada para o papel que não existe. A linha fora da faixa
    /// é recusada, no arquivo e no `policy.write`, que a aceita dentro dela.
    #[test]
    fn as_cotas_de_mensagens() {
        use crate::mensagens::{COTAS_PADRAO, Cotas, SEM_COTA, TETO_POR_CAIXA, TETO_POR_REMETENTE};
        let p = Politica::ler(crate::PADRAO).unwrap();
        for papel in ["observador", "operador", "sistema", "administrador"] {
            assert_eq!(p.papel(papel).unwrap().mensagens, COTAS_PADRAO, "{papel}");
        }
        let texto = alloc::format!(
            "{}mensagens operador 2 5\nmensagens sistema {TETO_POR_REMETENTE} {TETO_POR_CAIXA}\n",
            crate::PADRAO
        );
        let c = Politica::ler(&texto).unwrap();
        assert_eq!(
            c.papel("operador").unwrap().mensagens,
            Cotas {
                por_remetente: 2,
                por_caixa: 5
            }
        );
        // Do operador para o sistema: a de remetente do operador, a de caixa
        // do sistema. E ao contrário, o contrário.
        assert_eq!(
            c.cotas_de_mensagens(Some("operador"), Some("sistema")),
            Cotas {
                por_remetente: 2,
                por_caixa: TETO_POR_CAIXA
            }
        );
        assert_eq!(
            c.cotas_de_mensagens(Some("sistema"), Some("operador")),
            Cotas {
                por_remetente: TETO_POR_REMETENTE,
                por_caixa: 5
            }
        );
        // Sem papel, ou um que a política não tem: cota nenhuma.
        assert_eq!(c.cotas_de_mensagens(None, Some("fantasma")), SEM_COTA);
        for ruim in [
            "mensagens operador 0 5",
            "mensagens operador 2 0",
            "mensagens operador 33 5",
            "mensagens operador 2 65",
            "mensagens operador 2",
            "mensagens operador 2 5 9",
            "mensagens operador -1 5",
            "mensagens fantasma 2 5",
        ] {
            let texto = alloc::format!("{}\n{ruim}\n", crate::PADRAO);
            assert!(Politica::ler(&texto).is_err(), "{ruim}");
            assert!(
                p.com_linha(ruim, "administrador", &[]).is_err(),
                "policy.write {ruim}"
            );
        }
        let nova = p
            .com_linha("mensagens observador 1 3", "administrador", &[])
            .unwrap();
        assert_eq!(nova.papel("observador").unwrap().mensagens.por_caixa, 3);
        // E o papel protegido não muda, nem as cotas dele.
        assert!(
            p.com_linha("mensagens administrador 1 1", "administrador", &[])
                .is_err()
        );
    }

    /// O alcance de `message.send`: papéis enumerados, `papel:<nome>`, sem
    /// curinga. A política da imagem: o `sistema` alcança observador,
    /// operador, sistema e administrador; o `operador`, operador e sistema;
    /// o `observador` só lê; o `administrador`, operador, sistema e ele
    /// mesmo. Só o sistema e o próprio administrador alcançam o
    /// administrador.
    #[test]
    fn o_alcance_das_mensagens() {
        use Codigo::*;
        use Permissao::{MessagePurge, MessagePurgeMailbox, MessageRead, MessageSend};
        let p = Politica::ler(crate::PADRAO).unwrap();
        let manda = |papel: &str, alvo: &str| p.decidir(Some(papel), MessageSend, Some(alvo));
        for alvo in ["papel:observador", "papel:operador", "papel:sistema"] {
            assert_eq!(manda("sistema", alvo), Allow, "sistema -> {alvo}");
        }
        assert_eq!(manda("operador", "papel:operador"), Allow);
        assert_eq!(manda("operador", "papel:sistema"), Allow);
        assert_eq!(manda("operador", "papel:observador"), DenyResource);
        assert_eq!(manda("observador", "papel:operador"), DenyPermission);
        for papel in ["sistema", "administrador"] {
            assert_eq!(manda(papel, "papel:administrador"), Allow, "{papel}");
        }
        assert_eq!(manda("operador", "papel:administrador"), DenyResource);
        assert_eq!(manda("observador", "papel:administrador"), DenyPermission);
        assert_eq!(manda("administrador", "papel:observador"), DenyResource);
        for papel in ["sistema", "operador", "administrador"] {
            // Sem destinatário resolvido, nada; e nada de curinga.
            assert_eq!(manda(papel, ""), DenyResource);
            assert_eq!(p.decidir(Some(papel), MessageSend, None), DenyResource);
            assert_eq!(manda(papel, "papel:*"), DenyResource);
            assert_eq!(manda(papel, "*"), DenyResource);
            assert_eq!(manda(papel, "operador"), DenyResource);
        }
        // Um papel que a política em vigor não tem não é alcançado, mesmo
        // escrito no alcance.
        let fantasma = crate::PADRAO.replace(
            "recurso operador message.send papel:operador papel:sistema",
            "recurso operador message.send papel:operador papel:sistema papel:fantasma",
        );
        let f = Politica::ler(&fantasma).unwrap();
        assert_eq!(
            f.decidir(Some("operador"), MessageSend, Some("papel:fantasma")),
            DenyResource
        );
        // Ler a própria caixa: quem tem a permissão.
        for papel in ["observador", "operador", "sistema", "administrador"] {
            assert_eq!(p.decidir(Some(papel), MessageRead, None), Allow, "{papel}");
        }
        // Tirar a mensagem de outro, e esvaziar a caixa de outro: só o
        // administrador, e só com prova.
        for purga in [MessagePurge, MessagePurgeMailbox] {
            assert_eq!(p.decidir(Some("administrador"), purga, None), Allow);
            for papel in ["observador", "operador", "sistema"] {
                assert_eq!(
                    p.decidir(Some(papel), purga, None),
                    DenyPermission,
                    "{papel} {}",
                    purga.nome()
                );
            }
        }
        // Uma não traz a outra: o papel que tira uma mensagem não esvazia a
        // caixa, e o que esvazia não tira uma pelo id — cada uma escrita.
        let separadas = alloc::format!(
            "{}papel uma-so message.purge\npapel caixa-so message.purge_mailbox\n",
            crate::PADRAO
        );
        let s = Politica::ler(&separadas).unwrap();
        assert_eq!(s.decidir(Some("uma-so"), MessagePurge, None), Allow);
        assert_eq!(
            s.decidir(Some("uma-so"), MessagePurgeMailbox, None),
            DenyPermission
        );
        assert_eq!(
            s.decidir(Some("caixa-so"), MessagePurgeMailbox, None),
            Allow
        );
        assert_eq!(
            s.decidir(Some("caixa-so"), MessagePurge, None),
            DenyPermission
        );
        // Nem por inclusão: é sensível.
        let incluida = alloc::format!("{separadas}papel herdeiro @caixa-so\n");
        let h = Politica::ler(&incluida).unwrap();
        assert_eq!(
            h.decidir(Some("herdeiro"), MessagePurgeMailbox, None),
            DenyPermission
        );
    }

    /// A linha de alcance de rede: só destinos inteiros na forma normal,
    /// obrigatória para quem tem `net.connect`, e sensível — não vem por
    /// inclusão. Uma linha com um destino ambíguo recusa a política inteira.
    #[test]
    fn a_linha_de_destino_de_rede() {
        use Codigo::*;
        use Permissao::NetConnect;
        for ruim in [
            "recurso operador net.connect tcp:*:7",
            "recurso operador net.connect *",
            "recurso operador net.connect tcp:10.0.2.100:07",
            "recurso operador net.connect tcp:10.0.2.100",
            "recurso operador net.connect 10.0.2.100:7",
            "recurso operador net.connect /dados",
            "recurso operador net.connect papel:operador",
            "recurso operador net.connect",
        ] {
            let texto = alloc::format!("{}{ruim}\n", crate::PADRAO);
            let erro = Politica::ler(&texto).unwrap_err();
            assert!(
                matches!(
                    erro.tipo,
                    ErroTipo::EnderecoInvalido(_) | ErroTipo::Sintaxe | ErroTipo::Curinga
                ),
                "{ruim}: {erro:?}"
            );
        }
        // Sem a linha: recusada, não "qualquer destino".
        let sem = crate::PADRAO
            .lines()
            .filter(|l| !l.starts_with("recurso operador net.connect"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            Politica::ler(&sem).unwrap_err().tipo,
            ErroTipo::RecursoFaltando(_, _)
        ));
        // Mais de um destino, e repetido: lidos, sem duplicar.
        let dois = alloc::format!(
            "{}recurso operador net.connect tcp:10.0.2.100:7 tcp:10.0.2.2:80 tcp:10.0.2.100:7\n",
            crate::PADRAO
        );
        let p = Politica::ler(&dois).unwrap();
        assert_eq!(
            p.papel("operador")
                .unwrap()
                .recursos
                .get(&NetConnect)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            p.decidir(Some("operador"), NetConnect, Some("tcp:10.0.2.2:80")),
            Allow
        );
        // Sensível: por inclusão não vem.
        let incluida = alloc::format!(
            "{}papel conector net.connect\nrecurso conector net.connect tcp:10.0.2.100:7\npapel herdeiro @conector\n",
            crate::PADRAO
        );
        let h = Politica::ler(&incluida).unwrap();
        assert_eq!(
            h.decidir(Some("herdeiro"), NetConnect, Some("tcp:10.0.2.100:7")),
            DenyPermission
        );
    }

    /// A linha de alcance de destino: só `papel:<nome>`, com nome na regra,
    /// e obrigatória para quem tem `message.send` — também a que viria por
    /// inclusão, que não vem: as de mensagem são sensíveis.
    #[test]
    fn a_linha_de_destino() {
        for ruim in [
            "recurso operador message.send papel:*",
            "recurso operador message.send *",
            "recurso operador message.send operador",
            "recurso operador message.send /dados",
            "recurso operador message.send papel:",
            "recurso operador message.send papel:Nao-Vale",
            "recurso operador message.send",
            "recurso operador fs.read papel:operador",
            "recurso operador message.read papel:operador",
        ] {
            let texto = alloc::format!("{}\n{ruim}\n", crate::PADRAO);
            assert!(Politica::ler(&texto).is_err(), "{ruim}");
        }
        let sem = crate::PADRAO.replace(
            "recurso operador message.send papel:operador papel:sistema\n",
            "",
        );
        assert!(Politica::ler(&sem).is_err(), "message.send sem alcance");
        // A inclusão não traz mensagem: o papel que inclui o operador não
        // manda nem lê.
        let texto = alloc::format!(
            "{}\npapel herdeiro @operador\nrecurso herdeiro process.run /bin\n",
            crate::PADRAO
        );
        let h = Politica::ler(&texto).unwrap();
        assert!(!h.papel("herdeiro").unwrap().tem(Permissao::MessageSend));
        assert!(!h.papel("herdeiro").unwrap().tem(Permissao::MessageRead));
        assert_eq!(
            h.decidir(
                Some("herdeiro"),
                Permissao::MessageSend,
                Some("papel:operador")
            ),
            Codigo::DenyPermission
        );
    }

    /// Só o sistema e o próprio administrador alcançam o administrador: a
    /// política da imagem e a de emergência cumprem o invariante, e uma que
    /// o dê ao operador, ao observador ou a um papel qualquer não.
    #[test]
    fn so_o_sistema_e_o_administrador_alcancam_o_administrador() {
        for texto in [crate::PADRAO, crate::EMERGENCIA] {
            let p = Politica::ler(texto).unwrap();
            assert!(
                p.conferir_alcance_aos_administradores(&["administrador"])
                    .is_ok()
            );
        }
        let violadoras = [
            crate::PADRAO.replace(
                "recurso operador message.send papel:operador papel:sistema",
                "recurso operador message.send papel:operador papel:sistema papel:administrador",
            ),
            alloc::format!(
                "{}\npapel outro agent.read message.send\nrecurso outro message.send papel:administrador\n",
                crate::PADRAO
            ),
        ];
        for texto in &violadoras {
            let p = Politica::ler(texto).unwrap();
            let r = p.conferir_alcance_aos_administradores(&["administrador"]);
            assert!(
                matches!(&r, Err(m) if m.contains("papel:administrador")),
                "{r:?}"
            );
        }
        // O papel de uma chave de administrador com outro nome também.
        let chefe = alloc::format!(
            "{}\npapel chefe agent.read message.send message.read\nrecurso chefe message.send papel:chefe\n",
            crate::PADRAO.replace(
                "recurso operador message.send papel:operador papel:sistema",
                "recurso operador message.send papel:operador papel:sistema papel:chefe",
            )
        );
        let p = Politica::ler(&chefe).unwrap();
        assert!(
            p.conferir_alcance_aos_administradores(&["administrador"])
                .is_ok()
        );
        assert!(
            p.conferir_alcance_aos_administradores(&["administrador", "chefe"])
                .is_err()
        );
    }

    /// O teto: o administrador concede o que alcança. O operador cabe nele;
    /// um papel que alcançasse o observador não cabe. O alcance ao
    /// administrador está no teto — é o que torna representável o do
    /// sistema e o dele —, e ainda assim nenhum `policy.write` o dá a outro
    /// papel: nem ao operador, nem ao observador, nem a um papel novo.
    #[test]
    fn o_teto_das_mensagens() {
        let p = Politica::ler(crate::PADRAO).unwrap();
        assert!(p.cabe_em("operador", "administrador").is_ok());
        assert!(p.cabe_em("observador", "administrador").is_ok());
        for linha in [
            "recurso operador message.send papel:operador papel:sistema papel:administrador",
            "recurso operador message.send papel:administrador",
            "recurso operador message.send papel:operador papel:sistema papel:observador",
        ] {
            assert!(p.com_linha(linha, "administrador", &[]).is_err(), "{linha}");
        }
        // O operador, que já manda: o alcance ao administrador é recusado
        // pelo que é — e não por efeito de outra regra.
        let r = p.com_linha(
            "recurso operador message.send papel:operador papel:sistema papel:administrador",
            "administrador",
            &[],
        );
        assert!(
            matches!(&r, Err(Recusa::Proibida(m)) if m.contains("papel:administrador")),
            "{r:?}"
        );
        // O observador nem chega a mandar: `message.send` exige a linha de
        // alcance, e a linha de alcance exige a permissão — cada linha de
        // `policy.write` é validada sozinha, e nenhuma das duas passa.
        for linha in [
            "recurso observador message.send papel:administrador",
            "papel observador agent.read system.read log.read ui.read message.read message.send",
        ] {
            assert!(p.com_linha(linha, "administrador", &[]).is_err(), "{linha}");
        }
        // Encolher cabe.
        let menor = p
            .com_linha(
                "recurso operador message.send papel:sistema",
                "administrador",
                &[],
            )
            .unwrap();
        assert_eq!(
            menor.decidir(
                Some("operador"),
                Permissao::MessageSend,
                Some("papel:operador")
            ),
            Codigo::DenyResource
        );
    }

    /// A decisão fecha sozinha: um papel com permissão de caminho e sem
    /// alcance — que a validação não deixa existir — não alcança nada. É a
    /// segunda linha de defesa, e não pode virar "tudo" se a primeira um
    /// dia falhar.
    #[test]
    fn caminho_sem_alcance_nao_e_tudo_na_decisao() {
        let mut p = Politica::ler(crate::PADRAO).unwrap();
        let sistema = p.papel_mut("sistema").unwrap();
        sistema.recursos.remove(&Permissao::FsRead);
        assert!(p.papel("sistema").unwrap().tem(Permissao::FsRead));
        assert_eq!(
            p.decidir(Some("sistema"), Permissao::FsRead, Some("/dados/x")),
            Codigo::DenyResource
        );
    }
}
