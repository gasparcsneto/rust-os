//! O gestor de canisters: o pedido de quem opera e o registro dos
//! canisters de uma chave, em texto, no armazém. O programa `gestor` lê o
//! pedido, decide pelas regras daqui o que pode mandar ao IC, e grava o
//! registro e a resposta. Nada aqui assina, conecta ou lê arquivo: são as
//! contas, conferidas no hospedeiro.
//!
//! # O pedido
//!
//! ```text
//! # comentário
//! acao instalar
//! rede bancada
//! chave chave:bancada
//! canister lxzze-o7777-77777-aaaaa-cai
//! modulo /armazem/compartilhado/modulos/meu.wasm
//! sha256 9b6cc41ff390673f7c41030d1764a945419bff2dd7260bf37e8cb6a4e82d6590
//! modo reinstall
//! confirmar lxzze-o7777-77777-aaaaa-cai
//! ```
//!
//! Uma linha por campo, `<campo> <valor>`; só o `controlador` se repete.
//! Um campo que a ação não usa, um campo que falta, um valor fora da forma
//! ou um campo repetido recusam o pedido inteiro, com a linha: um pedido
//! meio lido seria uma operação que ninguém escreveu.
//!
//! | ação | o que faz | campos |
//! |---|---|---|
//! | `saldo` | o saldo da chave no ledger de ICP e no de cycles, por consulta assinada | — |
//! | `criar` | um canister novo, pago com cycles da chave | `ciclos`, `confirmar` = `ciclos` |
//! | `instalar` | o módulo no canister: `install`, `upgrade` ou `reinstall` | `canister`, `modulo`, `sha256`, `modo`, `argumento`?; no `reinstall`, `confirmar` = `canister` |
//! | `estado` | a situação, o módulo, os controladores, os cycles | `canister` |
//! | `parar`, `iniciar` | para e volta a executar | `canister` |
//! | `controladores` | troca os controladores | `canister`, `controlador`+, `confirmar` = `canister` |
//! | `congelamento` | o limiar de congelamento, em segundos | `canister`, `congelamento` |
//! | `desinstalar` | tira o módulo e o estado | `canister`, `confirmar` = `canister` |
//! | `apagar` | apaga o canister parado | `canister`, `confirmar` = `canister` |
//! | `carregar` | cycles da chave no canister, pelo ledger de cycles | `canister`, `ciclos`, `confirmar` = `ciclos` |
//! | `recarregar` | ICP da chave em cycles do canister, pelo CMC | `canister`, `icp`, `confirmar` = `icp` |
//!
//! Toda ação leva `rede` e `chave`; e, opcionalmente, `ancoras` — o
//! arquivo de âncoras do TLS — e `dns` — o resolvedor, `udp:<ipv4>:<porta>`.
//!
//! # As proteções
//!
//! O que não volta atrás pede `confirmar` com o que vai ser mexido, por
//! extenso: o canister de uma ação que apaga estado ou troca quem o
//! controla, e a quantia de uma que move valor. É contra o engano, e não
//! autoridade: quem decide se a chave assina continua sendo o gate, a cada
//! assinatura.
//!
//! A instalação diz o SHA-256 do módulo, e o programa só instala os bytes
//! que têm esse resumo: o arquivo do módulo pode estar onde outra pessoa
//! grava — o armazém compartilhado —, e o que a chave instala é o que o
//! pedido de quem a tem diz, e não o que estiver no caminho.
//!
//! E duas regras que o IC não tem: os controladores novos têm de incluir o
//! Principal da própria chave ([`conferir_controladores`]) — sem ele, a
//! chave se trancaria fora do canister, e nada a traria de volta —; e o
//! canister só se apaga parado, o que o programa confere antes.
//!
//! # O registro, e a repetição que não executa duas vezes
//!
//! O registro de uma chave numa rede guarda os canisters que ela criou ou
//! mexeu, e o último pedido: a versão dele no armazém, a ação, se acabou, a
//! hora com que foi assinado e o SHA-256 do texto dele — e, enquanto em
//! andamento, o próprio texto, conferido contra o SHA-256 a cada leitura:
//! quem precisar repeti-lo não depende de tê-lo guardado. Antes de mandar o
//! que muda alguma coisa, o programa grava o pedido como em andamento — com
//! a versão do registro que leu, e por isso dois programas não executam o
//! mesmo pedido. O plano ([`planejar`]):
//!
//! - o mesmo pedido — a mesma versão — que já acabou não executa de novo;
//! - o que ficou em andamento — o programa caiu, a rede caiu — retoma
//!   quando o pedido é **o mesmo texto**, de novo ou regravado: com **a
//!   mesma hora**, o `created_at_time` da criação, da carga e da
//!   transferência da recarga é o mesmo, e o ledger responde `Duplicate` em
//!   vez de executar duas vezes;
//! - com outro pedido em andamento, nada executa: um pedido novo por cima
//!   de uma criação que ninguém sabe se aconteceu perderia o canister dela.
//!   Repetir o pedido de antes — o texto está no registro — resolve, e
//!   depois o novo anda;
//! - o pedido novo executa com a hora de agora.
//!
//! O registro não é autoridade: quem controla um canister é um fato do IC,
//! e o programa age pelo canister do pedido, nunca pelo do registro.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::gerenciamento::{MAIS_CONTROLADORES, Modo};
use super::principal::Principal;
use super::resumo::Hash;

/// O maior pedido.
pub const MAIOR_PEDIDO: usize = 4 * 1024;

/// O maior registro.
pub const MAIOR_REGISTRO: usize = 64 * 1024;

/// Quantos canisters cabem no registro de uma chave numa rede.
pub const MAIS_CANISTERS: usize = 256;

/// O maior módulo que o gestor instala: 8 MiB, em pedaços de 1 MiB.
pub const MAIOR_MODULO: u64 = 8 * 1024 * 1024;

/// O maior argumento de instalação, em bytes.
pub const MAIOR_ARGUMENTO: usize = 1024;

/// O maior caminho de arquivo num pedido.
const MAIOR_CAMINHO: usize = 256;

/// O argumento vazio do Candid, `()`: o de uma instalação sem argumento.
pub const VAZIO: &[u8] = b"DIDL\x00\x00";

/// O que um pedido pede.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acao {
    /// O saldo da chave.
    Saldo,
    /// Um canister novo.
    Criar,
    /// Um módulo no canister.
    Instalar,
    /// O estado do canister.
    Estado,
    /// Parar o canister.
    Parar,
    /// Voltar a executar o canister.
    Iniciar,
    /// Trocar os controladores.
    Controladores,
    /// O limiar de congelamento.
    Congelamento,
    /// Tirar o módulo e o estado.
    Desinstalar,
    /// Apagar o canister.
    Apagar,
    /// Cycles da chave no canister.
    Carregar,
    /// ICP da chave em cycles do canister.
    Recarregar,
}

const ACOES: [(Acao, &str); 12] = [
    (Acao::Saldo, "saldo"),
    (Acao::Criar, "criar"),
    (Acao::Instalar, "instalar"),
    (Acao::Estado, "estado"),
    (Acao::Parar, "parar"),
    (Acao::Iniciar, "iniciar"),
    (Acao::Controladores, "controladores"),
    (Acao::Congelamento, "congelamento"),
    (Acao::Desinstalar, "desinstalar"),
    (Acao::Apagar, "apagar"),
    (Acao::Carregar, "carregar"),
    (Acao::Recarregar, "recarregar"),
];

impl Acao {
    /// O nome, como no pedido.
    pub fn nome(self) -> &'static str {
        ACOES
            .iter()
            .find(|(a, _)| *a == self)
            .map(|(_, n)| *n)
            .unwrap_or("?")
    }

    /// A ação deste nome.
    pub fn de(nome: &str) -> Option<Acao> {
        ACOES.iter().find(|(_, n)| *n == nome).map(|(a, _)| *a)
    }

    /// Só lê: não muda nada no IC, e executa de novo a cada pedido.
    pub fn so_le(self) -> bool {
        matches!(self, Acao::Saldo | Acao::Estado)
    }

    /// Age sobre um canister.
    fn tem_canister(self) -> bool {
        !matches!(self, Acao::Saldo | Acao::Criar)
    }
}

/// Um pedido lido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedido {
    /// A ação.
    pub acao: Acao,
    /// A rede, do arquivo de redes.
    pub rede: String,
    /// A chave, `chave:<nome>`.
    pub chave: String,
    /// O canister, nas ações sobre um.
    pub canister: Option<Principal>,
    /// O módulo, na instalação.
    pub modulo: Option<String>,
    /// O SHA-256 do módulo, na instalação.
    pub sha256: Option<Hash>,
    /// O modo, na instalação.
    pub modo: Option<Modo>,
    /// O argumento da instalação, em Candid; `()` sem ele.
    pub argumento: Vec<u8>,
    /// Os cycles, na criação e na carga.
    pub ciclos: Option<u128>,
    /// O ICP, em e8s, na recarga.
    pub icp: Option<u64>,
    /// Os controladores novos.
    pub controladores: Vec<Principal>,
    /// O limiar de congelamento, em segundos.
    pub congelamento: Option<u64>,
    /// O arquivo de âncoras do TLS, se não o padrão.
    pub ancoras: Option<String>,
    /// O resolvedor, se não o padrão.
    pub dns: Option<String>,
}

/// Por que um texto não vale: a linha (a partir de 1; zero é o texto
/// inteiro) e o motivo, em ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Erro {
    /// A linha.
    pub linha: usize,
    /// O motivo.
    pub motivo: &'static str,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.linha == 0 {
            f.write_str(self.motivo)
        } else {
            write!(f, "linha {}: {}", self.linha, self.motivo)
        }
    }
}

fn erro(linha: usize, motivo: &'static str) -> Erro {
    Erro { linha, motivo }
}

/// Um nome de rede: minúsculas, dígitos e `-`, de 1 a 32 — a regra do
/// arquivo de redes.
fn nome_de_rede(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Um caminho absoluto, de ASCII visível.
fn caminho(s: &str) -> bool {
    s.starts_with('/') && s.len() <= MAIOR_CAMINHO && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Hexadecimal minúsculo, de comprimento par.
fn de_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Um número decimal sem zeros à esquerda, maior que zero.
fn positivo(s: &str) -> Option<u128> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Um destino de resolvedor: `udp:<ipv4>:<porta>`.
fn destino_udp(s: &str) -> bool {
    let Some(resto) = s.strip_prefix("udp:") else {
        return false;
    };
    let Some((ip, porta)) = resto.rsplit_once(':') else {
        return false;
    };
    let partes: Vec<&str> = ip.split('.').collect();
    partes.len() == 4
        && partes.iter().all(|p| p.parse::<u8>().is_ok())
        && porta.parse::<u16>().is_ok_and(|p| p != 0)
}

/// Lê um pedido. Ver o cabeçalho do módulo.
pub fn ler_pedido(texto: &str) -> Result<Pedido, Erro> {
    if texto.len() > MAIOR_PEDIDO {
        return Err(erro(0, "pedido grande demais"));
    }
    let mut acao = None;
    let mut rede = None;
    let mut chave = None;
    let mut canister = None;
    let mut modulo = None;
    let mut sha256 = None;
    let mut modo = None;
    let mut argumento = None;
    let mut ciclos = None;
    let mut icp = None;
    let mut controladores: Vec<(usize, Principal)> = Vec::new();
    let mut congelamento = None;
    let mut confirmar = None;
    let mut ancoras = None;
    let mut dns = None;
    for (i, linha) in texto.lines().enumerate() {
        let n = i + 1;
        let linha = linha.trim_end_matches('\r');
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let (campo, valor) = linha.split_once(' ').ok_or(erro(n, "linha sem valor"))?;
        if valor.is_empty() || valor.contains(' ') {
            return Err(erro(n, "valor fora da forma"));
        }
        fn uma<T>(onde: &mut Option<(usize, T)>, n: usize, v: T) -> Result<(), Erro> {
            if onde.is_some() {
                return Err(erro(n, "campo repetido"));
            }
            *onde = Some((n, v));
            Ok(())
        }
        match campo {
            "acao" => {
                let a = Acao::de(valor).ok_or(erro(n, "acao desconhecida"))?;
                uma(&mut acao, n, a)?;
            }
            "rede" => {
                if !nome_de_rede(valor) {
                    return Err(erro(n, "nome de rede fora da forma"));
                }
                uma(&mut rede, n, String::from(valor))?;
            }
            "chave" => {
                let nome = valor
                    .strip_prefix("chave:")
                    .ok_or(erro(n, "chave sem o prefixo chave:"))?;
                if nome.is_empty() || nome.len() > 64 {
                    return Err(erro(n, "nome de chave fora da forma"));
                }
                uma(&mut chave, n, String::from(valor))?;
            }
            "canister" => {
                let p =
                    Principal::de_texto(valor).map_err(|_| erro(n, "canister fora da forma"))?;
                uma(&mut canister, n, p)?;
            }
            "modulo" => {
                if !caminho(valor) {
                    return Err(erro(n, "modulo sem caminho absoluto"));
                }
                uma(&mut modulo, n, String::from(valor))?;
            }
            "sha256" => {
                let h = de_hex(valor)
                    .and_then(|b| <Hash>::try_from(b.as_slice()).ok())
                    .ok_or(erro(n, "sha256 fora da forma"))?;
                uma(&mut sha256, n, h)?;
            }
            "modo" => {
                let m = match valor {
                    "install" => Modo::Instalar,
                    "upgrade" => Modo::Atualizar,
                    "reinstall" => Modo::Reinstalar,
                    _ => return Err(erro(n, "modo desconhecido")),
                };
                uma(&mut modo, n, m)?;
            }
            "argumento" => {
                let bytes = de_hex(valor).ok_or(erro(n, "argumento fora do hexadecimal"))?;
                if bytes.len() > MAIOR_ARGUMENTO || !bytes.starts_with(b"DIDL") {
                    return Err(erro(n, "argumento que nao e candid"));
                }
                uma(&mut argumento, n, bytes)?;
            }
            "ciclos" => {
                let c = positivo(valor).ok_or(erro(n, "ciclos fora da forma"))?;
                uma(&mut ciclos, n, c)?;
            }
            "icp" => {
                let e8s = positivo(valor)
                    .and_then(|v| u64::try_from(v).ok())
                    .ok_or(erro(n, "icp fora da forma"))?;
                uma(&mut icp, n, e8s)?;
            }
            "controlador" => {
                let p =
                    Principal::de_texto(valor).map_err(|_| erro(n, "controlador fora da forma"))?;
                if controladores.iter().any(|(_, c)| *c == p) {
                    return Err(erro(n, "controlador repetido"));
                }
                controladores.push((n, p));
            }
            "congelamento" => {
                let s = positivo(valor)
                    .and_then(|v| u64::try_from(v).ok())
                    .ok_or(erro(n, "congelamento fora da forma"))?;
                uma(&mut congelamento, n, s)?;
            }
            "confirmar" => uma(&mut confirmar, n, String::from(valor))?,
            "ancoras" => {
                if !caminho(valor) {
                    return Err(erro(n, "ancoras sem caminho absoluto"));
                }
                uma(&mut ancoras, n, String::from(valor))?;
            }
            "dns" => {
                if !destino_udp(valor) {
                    return Err(erro(n, "dns fora da forma udp:<ipv4>:<porta>"));
                }
                uma(&mut dns, n, String::from(valor))?;
            }
            _ => return Err(erro(n, "campo desconhecido")),
        }
    }
    let (_, acao) = acao.ok_or(erro(0, "pedido sem acao"))?;
    let (_, rede) = rede.ok_or(erro(0, "pedido sem rede"))?;
    let (_, chave) = chave.ok_or(erro(0, "pedido sem chave"))?;

    // Os campos que a ação usa, e os que ela não usa — o que sobra recusa.
    let usa = |campo: &str| -> bool {
        match campo {
            "canister" => acao.tem_canister(),
            "modulo" | "sha256" | "modo" | "argumento" => acao == Acao::Instalar,
            "ciclos" => matches!(acao, Acao::Criar | Acao::Carregar),
            "icp" => acao == Acao::Recarregar,
            "controlador" => acao == Acao::Controladores,
            "congelamento" => acao == Acao::Congelamento,
            _ => false,
        }
    };
    let sobra = |campo: &'static str, linha: Option<usize>| -> Result<(), Erro> {
        match linha {
            Some(n) if !usa(campo) => Err(erro(n, "campo que a acao nao usa")),
            _ => Ok(()),
        }
    };
    sobra("canister", canister.as_ref().map(|(n, _)| *n))?;
    sobra("modulo", modulo.as_ref().map(|(n, _)| *n))?;
    sobra("sha256", sha256.as_ref().map(|(n, _)| *n))?;
    sobra("modo", modo.as_ref().map(|(n, _)| *n))?;
    sobra("argumento", argumento.as_ref().map(|(n, _)| *n))?;
    sobra("ciclos", ciclos.as_ref().map(|(n, _)| *n))?;
    sobra("icp", icp.as_ref().map(|(n, _)| *n))?;
    sobra("controlador", controladores.first().map(|(n, _)| *n))?;
    sobra("congelamento", congelamento.as_ref().map(|(n, _)| *n))?;

    let falta = |campo: &'static str, presente: bool| -> Result<(), Erro> {
        if usa(campo) && !presente {
            return Err(Erro {
                linha: 0,
                motivo: match campo {
                    "canister" => "pedido sem canister",
                    "modulo" => "pedido sem modulo",
                    "sha256" => "pedido sem sha256",
                    "modo" => "pedido sem modo",
                    "ciclos" => "pedido sem ciclos",
                    "icp" => "pedido sem icp",
                    "controlador" => "pedido sem controlador",
                    _ => "pedido sem congelamento",
                },
            });
        }
        Ok(())
    };
    falta("canister", canister.is_some())?;
    falta("modulo", modulo.is_some())?;
    falta("sha256", sha256.is_some())?;
    falta("modo", modo.is_some())?;
    falta("ciclos", ciclos.is_some())?;
    falta("icp", icp.is_some())?;
    falta("controlador", !controladores.is_empty())?;
    falta("congelamento", congelamento.is_some())?;
    if controladores.len() > MAIS_CONTROLADORES {
        return Err(erro(
            controladores[MAIS_CONTROLADORES].0,
            "mais de 10 controladores",
        ));
    }

    let canister = canister.map(|(_, c)| c);
    let ciclos = ciclos.map(|(_, c)| c);
    let icp = icp.map(|(_, c)| c);
    let modo = modo.map(|(_, m)| m);

    // A confirmação: o que vai ser mexido, por extenso — ou nada.
    let esperada = match acao {
        Acao::Criar | Acao::Carregar => ciclos.map(|c| alloc::format!("{c}")),
        Acao::Recarregar => icp.map(|c| alloc::format!("{c}")),
        Acao::Controladores | Acao::Desinstalar | Acao::Apagar => canister.map(|c| c.texto()),
        Acao::Instalar if modo == Some(Modo::Reinstalar) => canister.map(|c| c.texto()),
        _ => None,
    };
    match (esperada, confirmar) {
        (None, None) => {}
        (None, Some((n, _))) => return Err(erro(n, "confirmar numa acao que nao pede")),
        (Some(_), None) => return Err(erro(0, "pedido sem confirmar")),
        (Some(e), Some((n, c))) => {
            if e != c {
                return Err(erro(n, "confirmar nao e o que a acao mexe"));
            }
        }
    }

    Ok(Pedido {
        acao,
        rede,
        chave,
        canister,
        modulo: modulo.map(|(_, m)| m),
        sha256: sha256.map(|(_, h)| h),
        modo,
        argumento: argumento.map_or_else(|| Vec::from(VAZIO), |(_, a)| a),
        ciclos,
        icp,
        controladores: controladores.into_iter().map(|(_, c)| c).collect(),
        congelamento: congelamento.map(|(_, c)| c),
        ancoras: ancoras.map(|(_, a)| a),
        dns: dns.map(|(_, d)| d),
    })
}

/// Confere os controladores novos contra o Principal da chave que vai
/// assinar: sem ele na lista, a chave se trancaria fora do canister.
pub fn conferir_controladores(pedido: &Pedido, da_chave: &Principal) -> Result<(), &'static str> {
    if pedido.acao != Acao::Controladores {
        return Ok(());
    }
    if pedido.controladores.contains(da_chave) {
        Ok(())
    } else {
        Err("os controladores novos nao incluem a propria chave")
    }
}

/// A situação de um canister no registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Situacao {
    /// Executando — ou a última notícia não disse o contrário.
    Ativo,
    /// Parado pelo gestor.
    Parado,
    /// Apagado pelo gestor.
    Apagado,
}

impl Situacao {
    /// O nome, como no registro.
    pub fn nome(self) -> &'static str {
        match self {
            Situacao::Ativo => "ativo",
            Situacao::Parado => "parado",
            Situacao::Apagado => "apagado",
        }
    }

    fn de(nome: &str) -> Option<Situacao> {
        match nome {
            "ativo" => Some(Situacao::Ativo),
            "parado" => Some(Situacao::Parado),
            "apagado" => Some(Situacao::Apagado),
            _ => None,
        }
    }
}

/// Um canister do registro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canister {
    /// O canister.
    pub id: Principal,
    /// A situação.
    pub situacao: Situacao,
    /// O hash do módulo que o gestor instalou; nenhum, sem módulo.
    pub modulo: Option<Hash>,
    /// A hora da última mudança, em ns.
    pub ns: u64,
}

/// Se o último pedido acabou — e, enquanto não, o texto dele.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fase {
    /// Acabou: o desfecho foi provado.
    Feito,
    /// Em andamento — o programa caiu, a rede caiu, ou o desfecho não se
    /// provou —, com o texto do pedido: quem for repeti-lo o tem aqui, e
    /// o SHA-256 dele é o [`Ultimo::resumo`].
    Andamento(String),
}

/// O último pedido de quem muda alguma coisa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ultimo {
    /// A versão do pedido no armazém.
    pub pedido: u64,
    /// A ação.
    pub acao: Acao,
    /// Se acabou.
    pub fase: Fase,
    /// A hora com que se assina — o `created_at_time` da criação, da
    /// carga e da transferência da recarga.
    pub criado_em_ns: u64,
    /// O SHA-256 do texto do pedido: o mesmo texto retoma.
    pub resumo: Hash,
}

impl Ultimo {
    /// Acabou.
    pub fn feito(&self) -> bool {
        self.fase == Fase::Feito
    }

    /// O texto do pedido, enquanto em andamento.
    pub fn pendente(&self) -> Option<&str> {
        match &self.fase {
            Fase::Feito => None,
            Fase::Andamento(t) => Some(t),
        }
    }
}

/// O registro dos canisters de uma chave numa rede.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registro {
    /// Os canisters, na ordem em que entraram.
    pub canisters: Vec<Canister>,
    /// O último pedido que muda alguma coisa.
    pub ultimo: Option<Ultimo>,
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// O cabeçalho que todo registro tem.
pub const CABECALHO: &str = "# registro do gestor de canisters";

impl Registro {
    /// O canister `id`, se está no registro.
    pub fn canister(&self, id: &Principal) -> Option<&Canister> {
        self.canisters.iter().find(|c| c.id == *id)
    }

    /// Anota o `canister`: no lugar do que tinha o mesmo id, ou no fim.
    pub fn anotar(&mut self, canister: Canister) -> Result<(), &'static str> {
        if let Some(c) = self.canisters.iter_mut().find(|c| c.id == canister.id) {
            *c = canister;
            return Ok(());
        }
        if self.canisters.len() >= MAIS_CANISTERS {
            return Err("o registro tem canisters demais");
        }
        self.canisters.push(canister);
        Ok(())
    }

    /// O registro em texto: o que [`ler_registro`] lê.
    pub fn texto(&self) -> String {
        let mut s = String::from(CABECALHO);
        s.push('\n');
        for c in &self.canisters {
            s.push_str(&alloc::format!(
                "canister {} {} {} {}\n",
                c.id.texto(),
                c.situacao.nome(),
                c.modulo.map_or(String::from("nenhum"), |h| hex(&h)),
                c.ns
            ));
        }
        if let Some(u) = &self.ultimo {
            s.push_str(&alloc::format!(
                "ultimo {} {} {} {} {}",
                u.pedido,
                u.acao.nome(),
                if u.feito() { "feito" } else { "andamento" },
                u.criado_em_ns,
                hex(&u.resumo)
            ));
            if let Fase::Andamento(texto) = &u.fase {
                s.push(' ');
                s.push_str(&hex(texto.as_bytes()));
            }
            s.push('\n');
        }
        s
    }
}

/// Lê um registro. **Qualquer erro recusa o registro inteiro**: o programa
/// não age sobre um registro que não entende, nem o sobrescreve — o que
/// está lá fica para quem for olhar.
pub fn ler_registro(texto: &str) -> Result<Registro, Erro> {
    if texto.len() > MAIOR_REGISTRO {
        return Err(erro(0, "registro grande demais"));
    }
    let mut linhas = texto.lines().enumerate();
    match linhas.next() {
        Some((_, l)) if l == CABECALHO => {}
        _ => return Err(erro(1, "registro sem o cabecalho")),
    }
    let mut r = Registro::default();
    for (i, linha) in linhas {
        let n = i + 1;
        let partes: Vec<&str> = linha.split(' ').collect();
        match partes.as_slice() {
            ["canister", id, situacao, modulo, ns] => {
                if r.ultimo.is_some() {
                    return Err(erro(n, "canister depois do ultimo"));
                }
                let id = Principal::de_texto(id).map_err(|_| erro(n, "canister fora da forma"))?;
                if r.canister(&id).is_some() {
                    return Err(erro(n, "canister repetido"));
                }
                let situacao = Situacao::de(situacao).ok_or(erro(n, "situacao desconhecida"))?;
                let modulo = match *modulo {
                    "nenhum" => None,
                    h => Some(
                        de_hex(h)
                            .and_then(|b| <Hash>::try_from(b.as_slice()).ok())
                            .ok_or(erro(n, "hash do modulo fora da forma"))?,
                    ),
                };
                let ns = ns.parse().map_err(|_| erro(n, "hora fora da forma"))?;
                if r.canisters.len() >= MAIS_CANISTERS {
                    return Err(erro(n, "o registro tem canisters demais"));
                }
                r.canisters.push(Canister {
                    id,
                    situacao,
                    modulo,
                    ns,
                });
            }
            ["ultimo", pedido, acao, estado, criado, resumo, resto @ ..] => {
                if r.ultimo.is_some() {
                    return Err(erro(n, "ultimo repetido"));
                }
                let acao = Acao::de(acao).ok_or(erro(n, "acao desconhecida"))?;
                if acao.so_le() {
                    return Err(erro(n, "ultimo de uma acao que so le"));
                }
                let pedido = pedido
                    .parse()
                    .map_err(|_| erro(n, "versao fora da forma"))?;
                let criado_em_ns = criado.parse().map_err(|_| erro(n, "hora fora da forma"))?;
                let resumo = de_hex(resumo)
                    .and_then(|b| <Hash>::try_from(b.as_slice()).ok())
                    .ok_or(erro(n, "resumo do pedido fora da forma"))?;
                let fase = match (*estado, resto) {
                    ("feito", []) => Fase::Feito,
                    ("andamento", [texto]) => Fase::Andamento(texto_pendente(texto, &resumo, n)?),
                    ("feito" | "andamento", _) => return Err(erro(n, "linha fora da forma")),
                    _ => return Err(erro(n, "estado do ultimo desconhecido")),
                };
                r.ultimo = Some(Ultimo {
                    pedido,
                    acao,
                    fase,
                    criado_em_ns,
                    resumo,
                });
            }
            _ => return Err(erro(n, "linha fora da forma")),
        }
    }
    Ok(r)
}

/// O texto do pedido em andamento, em hexadecimal no registro: um pedido
/// em UTF-8, do tamanho de um, cujo SHA-256 é o `resumo` da linha.
fn texto_pendente(hex: &str, resumo: &Hash, n: usize) -> Result<String, Erro> {
    let bytes = de_hex(hex).ok_or(erro(n, "texto do pedido fora da forma"))?;
    if bytes.is_empty() || bytes.len() > MAIOR_PEDIDO {
        return Err(erro(n, "texto do pedido fora da forma"));
    }
    if super::resumo::sha256(&bytes) != *resumo {
        return Err(erro(n, "o texto do pedido nao e o do resumo"));
    }
    String::from_utf8(bytes).map_err(|_| erro(n, "texto do pedido fora da forma"))
}

/// O que fazer com o pedido de versão `versao`, pelo registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plano {
    /// Executar, assinando com esta hora.
    Executar {
        /// A hora, em ns.
        criado_em_ns: u64,
    },
    /// Retomar o que ficou em andamento, com a hora de antes.
    Retomar {
        /// A hora, em ns.
        criado_em_ns: u64,
    },
    /// Já acabou: não executa de novo.
    JaFeito,
    /// Outro pedido ficou em andamento: este não executa até aquele ser
    /// repetido.
    Bloqueado {
        /// A ação do que ficou em andamento.
        pendente: Acao,
        /// A versão dele.
        versao: u64,
    },
}

/// O plano do pedido de versão `versao`, ação `acao` e texto de SHA-256
/// `resumo`, pelo `registro`, com a hora `agora_ns` — ver o cabeçalho do
/// módulo. O que só lê executa sempre.
pub fn planejar(
    versao: u64,
    acao: Acao,
    resumo: &Hash,
    registro: &Registro,
    agora_ns: u64,
) -> Plano {
    let agora = Plano::Executar {
        criado_em_ns: agora_ns,
    };
    if acao.so_le() {
        return agora;
    }
    match &registro.ultimo {
        Some(u) if !u.feito() && u.resumo == *resumo => Plano::Retomar {
            criado_em_ns: u.criado_em_ns,
        },
        Some(u) if !u.feito() => Plano::Bloqueado {
            pendente: u.acao,
            versao: u.pedido,
        },
        Some(u) if u.pedido == versao => Plano::JaFeito,
        _ => agora,
    }
}

#[cfg(test)]
mod testes;
