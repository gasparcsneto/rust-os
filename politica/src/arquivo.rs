//! A política: o arquivo, a validação, a decisão e as mudanças.
//!
//! # O formato
//!
//! ```text
//! # comentário
//! papel observador agent.read system.read log.read ui.read
//! papel operador @observador ui.act process.run net.send fs.read
//! recurso operador fs.read /dados /bin /programas
//! taxa operador 50 100
//! apertos 10 10000
//! serial sistema
//! ```
//!
//! - `papel <nome> <item>...`: um item é uma permissão do vocabulário ou
//!   `@<papel>`, a inclusão de outro papel. A inclusão traz só as permissões
//!   **não sensíveis** do outro: uma sensível precisa estar escrita em cada
//!   papel que a tem. Não há curinga — `*` é um erro com nome próprio.
//! - `recurso <papel> <permissão> <prefixo>...`: limita uma permissão cujo
//!   recurso é um caminho aos prefixos dados.
//! - `taxa <papel> <por segundo> <rajada>`: o balde de pedidos do papel.
//! - `apertos <quantos> <janela em ms>`: apertos de mão por porta.
//! - `serial <papel>`: o papel da sessão 0. Obrigatória.
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
    apertos: Apertos,
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
    CaminhoInvalido(String),
    /// Falta a linha `serial`.
    SemSerial,
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
            ErroTipo::RecursoNaoECaminho(p) => format!("o recurso de `{p}` nao e caminho"),
            ErroTipo::CaminhoInvalido(c) => format!("caminho invalido `{c}`"),
            ErroTipo::SemSerial => "falta a linha `serial`".to_string(),
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
            apertos: APERTOS_PADRAO,
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
        p.validar()?;
        Ok(p)
    }

    /// A política de emergência: o que vale quando a do disco falta ou não
    /// se lê. Um papel só, de leitura, e é o da serial — as portas não têm
    /// papel nenhum e recusam tudo. Falhar fechado: sem política não se
    /// adivinha uma.
    pub fn emergencia() -> Politica {
        let mut papel = Papel::novo("emergencia");
        papel.diretas = alloc::vec![
            Permissao::AgentRead,
            Permissao::SystemRead,
            Permissao::LogRead,
            Permissao::AuditRead,
        ];
        let mut p = Politica {
            papeis: alloc::vec![papel],
            serial: "emergencia".to_string(),
            apertos: APERTOS_PADRAO,
        };
        // Não falha: o papel é fixo e válido.
        let _ = p.validar();
        p
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

    /// O limite de apertos por porta.
    pub fn apertos(&self) -> Apertos {
        self.apertos
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
                if !p.recurso_e_caminho() {
                    return Err(erro(ErroTipo::RecursoNaoECaminho(p.nome().to_string())));
                }
                let mut prefixos = Vec::new();
                for c in partes {
                    let normal = caminho::normalizar(c)
                        .ok_or(erro(ErroTipo::CaminhoInvalido(c.to_string())))?;
                    prefixos.push(normal);
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
            "serial" => {
                let nome = partes.next().ok_or(erro(ErroTipo::Sintaxe))?;
                if partes.next().is_some() {
                    return Err(erro(ErroTipo::Sintaxe));
                }
                self.serial = nome.to_string();
            }
            _ => return Err(erro(ErroTipo::LinhaDesconhecida)),
        }
        Ok(())
    }

    /// Confere o que só se confere com tudo lido, e calcula as permissões.
    fn validar(&mut self) -> Result<(), Erro> {
        let geral = |tipo| Erro { linha: 0, tipo };
        if self.papel(&self.serial).is_none() {
            return Err(geral(ErroTipo::PapelDesconhecido(self.serial.clone())));
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
    /// `DENY_ROLE`. Sem a permissão: `DENY_PERMISSION`. Com a permissão
    /// limitada e o recurso fora dos prefixos — ou ausente, ou que não se
    /// normaliza —: `DENY_RESOURCE`.
    pub fn decidir(&self, papel: Option<&str>, p: Permissao, recurso: Option<&str>) -> Codigo {
        let Some(papel) = papel.and_then(|n| self.papel(n)) else {
            return Codigo::DenyRole;
        };
        if !papel.tem(p) {
            return Codigo::DenyPermission;
        }
        if let Some(prefixos) = papel.recursos.get(&p) {
            let Some(normal) = recurso.and_then(caminho::normalizar) else {
                return Codigo::DenyResource;
            };
            if !prefixos.iter().any(|pre| caminho::dentro_de(&normal, pre)) {
                return Codigo::DenyResource;
            }
        }
        Codigo::Allow
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
        for p in a.permissoes() {
            if !t.tem(p) {
                return Err(Recusa::Proibida(format!(
                    "`{papel}` tem `{}`, que o administrador nao tem",
                    p.nome()
                )));
            }
            if !recurso_contido(a.recursos.get(&p), t.recursos.get(&p)) {
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
        if !matches!(palavra, "papel" | "recurso" | "taxa") {
            return Err(Recusa::Proibida(
                "policy.write muda papel, recurso ou taxa; a serial muda por policy.assign"
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
            for p in depois.permissoes() {
                let ja_tinha = antes.is_some_and(|a| a.tem(p));
                let alargou = antes.is_some_and(|a| {
                    a.tem(p) && !recurso_contido(depois.recursos.get(&p), a.recursos.get(&p))
                });
                if !ja_tinha && !t.tem(p) {
                    return Err(Recusa::Proibida(format!(
                        "a mudanca daria `{}` a `{}`, e o administrador nao a tem",
                        p.nome(),
                        depois.nome
                    )));
                }
                if (!ja_tinha || alargou)
                    && !recurso_contido(depois.recursos.get(&p), t.recursos.get(&p))
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

/// O limite `a` está contido no limite `b`. `None` é sem limite: contém
/// tudo e só está contido em outro sem limite.
fn recurso_contido(a: Option<&Vec<String>>, b: Option<&Vec<String>>) -> bool {
    match (a, b) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a
            .iter()
            .all(|pa| b.iter().any(|pb| caminho::dentro_de(pa, pb))),
    }
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
