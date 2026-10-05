//! O armazém no kernel: a árvore gravável, montada em `/armazem`.
//!
//! A conta — caminhos, versões, tetos — é a do pacote `armazem`; aqui ela
//! encontra o resto, e cada coisa no seu lugar, como `docs/ARMAZENAMENTO.md`
//! as separa:
//!
//! | conceito | onde |
//! |---|---|
//! | autorização e alcance de caminho | o gate, antes do handler: `fs.write` (ou `fs.read`) no papel ∩ manifesto, sobre o `path` do pedido |
//! | arrendamento | [`crate::coordenacao`], recurso `fs:<caminho>` — só o arrendamento |
//! | versão | o armazém: a versão do objeto, de um contador do armazém inteiro |
//! | persistência | [`crate::persistencia::gravar_armazem`], estrita |
//! | auditoria | a decisão do gate, e o que o comando fez, no mesmo registro do journal que a mudança |
//!
//! Este módulo não decide quem pode: chega aqui só o que o gate já
//! autorizou, e ele não tem exceção para ninguém — nem para o `sistema`,
//! que não arrenda, e por isso só muda um objeto livre.
//!
//! # A ordem de uma mutação
//!
//! Tudo com a ordem das gravações na mão ([`crate::persistencia::em_ordem`]),
//! do começo ao fim, para nada mudar entre o que se conferiu e o que se
//! gravou:
//!
//! 1. a persistência está disponível? — senão `ERROR`, e nada muda;
//! 2. o arrendamento: o de outro titular recusa (`CONFLICT`);
//! 3. a versão esperada é a de agora? — senão `CONFLICT`;
//! 4. o armazém prepara a mudança (caminho, tipo, tetos), sem aplicá-la;
//! 5. a auditoria registra o que o comando vai fazer, em nome de quem o gate
//!    autorizou, com o número da decisão; e a mudança vai para o journal
//!    num registro que leva esse registro da auditoria — e, antes dele na
//!    cadeia, a decisão;
//! 6. só depois de gravada, a mudança vale em memória.
//!
//! Cada recusa depois do gate também vai para a auditoria, como o resultado
//! do comando autorizado.
//!
//! # A leitura
//!
//! Pelo VFS, como qualquer arquivo: `fs.read`, `fs.list` e o `abrir` dos
//! processos, cada um pelo gate de sempre. O nó de um arquivo é a versão
//! dele — ver o pacote `armazem` —: um descritor aberto num conteúdo que
//! mudou recebe [`crate::vfs::Erro::Mudou`], e nunca metade de um conteúdo
//! e metade de outro.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use ::armazem::{Armazem, Mudanca, Recusa, Tipo};
use politica::Codigo;
use politica::arrendamento::{Arrendamento, Titular};

use crate::trava::Mutex;
use crate::vfs::{self, Entrada, No, SistemaDeArquivos};

/// Onde o armazém está montado.
pub const RAIZ: &str = "/armazem";

static ARMAZEM: Mutex<Armazem> = Mutex::new(Armazem::novo());

/// Roda `f` com o armazém. Curto: o que for longo — o disco — se faz fora.
pub fn com_o_armazem<R>(f: impl FnOnce(&Armazem) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&ARMAZEM.lock()))
}

fn com_o_armazem_mut<R>(f: impl FnOnce(&mut Armazem) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ARMAZEM.lock()))
}

/// Repõe uma mudança lida do journal, no boot. Uma que o armazém recusa —
/// fora de ordem, num lugar que não pode ser, além de um teto — é um
/// journal que não se explica, e a abertura da persistência o trata como
/// trata qualquer entrada que não se reaplica.
pub(crate) fn restaurar(m: &Mudanca) -> Result<(), &'static str> {
    com_o_armazem_mut(|a| a.aplicar(m)).map_err(Recusa::motivo)
}

/// Repõe a próxima versão, da base de uma compactação.
pub(crate) fn fixar_proxima(n: u64) {
    com_o_armazem_mut(|a| a.fixar_proxima(n));
}

/// Monta o armazém em [`RAIZ`]. No boot, antes de a persistência repô-lo.
pub fn montar() -> Result<(), vfs::Erro> {
    vfs::montar("armazem", RAIZ, Box::new(NoVfs))
}

/// O caminho do armazém, relativo à raiz dele, de um caminho do pedido — na
/// forma normal da política, a mesma que o gate conferiu. `None` para o que
/// não está abaixo de [`RAIZ`].
///
/// Devolve também a forma normal inteira, que é o nome do recurso do
/// arrendamento e o que vai para a auditoria.
pub fn relativo(caminho: &str) -> Option<(String, String)> {
    let normal = politica::caminho::normalizar(caminho)?;
    let resto = normal.strip_prefix(RAIZ)?.strip_prefix('/')?;
    let resto = String::from(resto);
    Some((normal, resto))
}

/// Uma mutação pedida.
pub enum Operacao<'a> {
    /// Cria (`esperada` 0) ou substitui o conteúdo inteiro.
    Gravar(&'a [u8]),
    /// Acrescenta ao fim de um arquivo que existe.
    Acrescentar(&'a [u8]),
    /// Apaga um arquivo que existe.
    Apagar,
}

/// Uma mutação feita: a versão que o objeto passou a ter, e o tamanho
/// dele — zero, apagado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feita {
    pub versao: u64,
    pub tamanho: usize,
}

/// Por que uma mutação autorizada não aconteceu. Cada uma é de um conceito
/// só, com o código dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O caminho não é de um arquivo do armazém.
    Caminho(&'static str),
    /// A persistência não está disponível, ou a gravação falhou.
    Persistencia(&'static str),
    /// Outro titular tem o arrendamento.
    Arrendamento(Titular),
    /// A versão esperada não é a de agora.
    Versao { atual: u64 },
    /// O armazém recusou: o lugar, o tipo, um teto.
    Armazem(Recusa),
    /// Não há o registro da auditoria do comando — chamada fora de um
    /// comando autorizado.
    SemAuditoria,
}

impl Falha {
    /// O código, como a auditoria e a resposta o dizem.
    pub fn codigo(self) -> Codigo {
        match self {
            Falha::Caminho(_) => Codigo::InvalidArgument,
            Falha::Persistencia(_) | Falha::SemAuditoria => Codigo::Error,
            Falha::Arrendamento(_) | Falha::Versao { .. } => Codigo::Conflict,
            Falha::Armazem(Recusa::Cheio) => Codigo::Error,
            Falha::Armazem(_) => Codigo::InvalidArgument,
        }
    }

    /// O motivo, em palavras.
    pub fn motivo(self) -> &'static str {
        match self {
            Falha::Caminho(m) | Falha::Persistencia(m) => m,
            Falha::Arrendamento(_) => "outro titular tem o arrendamento",
            Falha::Versao { .. } => "a versao esperada nao e a de agora",
            Falha::Armazem(r) => r.motivo(),
            Falha::SemAuditoria => "a mudanca nao tem o registro da auditoria do comando",
        }
    }

    /// Qual conflito, quando é um: `lease` ou `version`.
    pub fn conflito(self) -> Option<&'static str> {
        match self {
            Falha::Arrendamento(_) => Some("lease"),
            Falha::Versao { .. } => Some("version"),
            _ => None,
        }
    }
}

impl From<Recusa> for Falha {
    fn from(r: Recusa) -> Falha {
        match r {
            Recusa::Versao { atual } => Falha::Versao { atual },
            outra => Falha::Armazem(outra),
        }
    }
}

/// O titular de quem o comando em execução age por — `None` para quem não
/// arrenda, o `sistema`.
fn titular() -> Option<Titular> {
    crate::coordenacao::titular_da_autoridade(crate::autorizacao::autoridade_atual())
}

/// Registra o resultado de uma mutação recusada depois do gate.
fn recusada(normal: &str, f: Falha) -> Falha {
    let detalhe = match f {
        Falha::Versao { atual } => format!("{}; versao atual {atual}", f.motivo()),
        _ => String::from(f.motivo()),
    };
    crate::autorizacao::auditar_execucao(normal, f.codigo(), &detalhe);
    f
}

/// Faz uma mutação pedida pelo comando em execução neste fio, contra a
/// versão `esperada`. Ver a ordem no topo do módulo.
pub fn mudar(caminho: &str, esperada: u64, op: Operacao) -> Result<Feita, Falha> {
    let Some((normal, relativo)) = relativo(caminho) else {
        let f = Falha::Caminho("o caminho nao e de um arquivo do armazem");
        return Err(recusada(caminho, f));
    };
    let titular = titular();
    crate::persistencia::em_ordem(|| {
        if let Err(m) = crate::persistencia::exigir() {
            return Err(recusada(&normal, Falha::Persistencia(m)));
        }
        let recurso = crate::coordenacao::recurso_do_caminho(&normal);
        if let Err(r) = crate::coordenacao::conferir(&recurso, titular) {
            let dono = match r {
                politica::arrendamento::Recusa::Ocupado(t) => t,
                // `conferir` só recusa por outro titular.
                _ => return Err(recusada(&normal, Falha::Persistencia(r.motivo()))),
            };
            return Err(recusada(&normal, Falha::Arrendamento(dono)));
        }
        let preparada = com_o_armazem(|a| match op {
            Operacao::Gravar(dados) => a.preparar_gravacao(&relativo, esperada, dados),
            Operacao::Acrescentar(mais) => a.preparar_acrescimo(&relativo, esperada, mais),
            Operacao::Apagar => a.preparar_remocao(&relativo, esperada),
        });
        let mudanca = match preparada {
            Ok(m) => m,
            Err(r) => return Err(recusada(&normal, r.into())),
        };
        let feita = Feita {
            versao: mudanca.versao(),
            tamanho: match &mudanca {
                Mudanca::Gravado { dados, .. } => dados.len(),
                Mudanca::Apagado { .. } => 0,
            },
        };
        // O que o comando vai fazer, em nome de quem o gate autorizou: este
        // registro vai no mesmo registro do journal que a mudança, e a
        // decisão, antes dele na cadeia, nunca depois.
        let execucao = crate::autorizacao::auditar_execucao(
            &normal,
            Codigo::Allow,
            &format!("mudanca a gravar: versao {}", feita.versao),
        );
        if execucao == 0 {
            return Err(Falha::SemAuditoria);
        }
        if let Err(m) = crate::persistencia::gravar_armazem(&mudanca, execucao) {
            return Err(recusada(&normal, Falha::Persistencia(m)));
        }
        // Gravada. Com a ordem na mão nada mais mudou o armazém desde a
        // preparação, e a aplicação não recusa; se recusasse, o disco teria
        // o que a memória não tem, e o boot seguinte o repõe.
        if let Err(r) = com_o_armazem_mut(|a| a.aplicar(&mudanca)) {
            crate::log_error!(
                "armazem",
                "a mudanca gravada nao se aplicou em memoria: {}",
                r.motivo()
            );
            return Err(recusada(&normal, Falha::Armazem(r)));
        }
        Ok(feita)
    })
}

/// O que se sabe de um caminho: o tipo, a versão e o tamanho.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Situacao {
    pub tipo: Option<Tipo>,
    pub versao: u64,
    pub tamanho: usize,
    pub arrendamento: Option<Arrendamento>,
}

/// A situação de um caminho do armazém, ou `None` se ele não é do armazém.
pub fn situacao(caminho: &str) -> Option<(String, Situacao)> {
    let (normal, relativo) = match relativo(caminho) {
        Some(r) => r,
        // A raiz do armazém é dele também: um diretório, sempre.
        None if politica::caminho::normalizar(caminho)? == RAIZ => {
            (String::from(RAIZ), String::new())
        }
        None => return None,
    };
    let (tipo, versao, tamanho) = com_o_armazem(|a| {
        (
            a.tipo(&relativo),
            a.versao(&relativo),
            a.objeto(&relativo).map_or(0, |o| o.dados().len()),
        )
    });
    let arrendamento =
        crate::coordenacao::estado(&crate::coordenacao::recurso_do_caminho(&normal)).arrendamento;
    Some((
        normal,
        Situacao {
            tipo,
            versao,
            tamanho,
            arrendamento,
        },
    ))
}

/// Uma recusa de `fs.claim` ou `fs.release` que não veio da tabela —
/// o caminho, quem não arrenda —, gravada como o resultado do comando. As
/// da tabela, a coordenação já grava, em nome do titular.
fn recusa_fora_da_tabela(
    caminho: &str,
    codigo: Codigo,
    motivo: &'static str,
) -> (Codigo, &'static str) {
    crate::autorizacao::auditar_execucao(caminho, codigo, motivo);
    (codigo, motivo)
}

/// Toma o arrendamento de um caminho do armazém para quem o comando age.
/// O caminho pode ainda não ter arquivo — quem vai criá-lo o arrenda antes —,
/// mas não pode ser um diretório.
pub fn arrendar(caminho: &str, prazo_ms: u64) -> Result<Arrendamento, (Codigo, &'static str)> {
    let Some((normal, relativo)) = relativo(caminho).filter(|(_, r)| ::armazem::caminho_valido(r))
    else {
        return Err(recusa_fora_da_tabela(
            caminho,
            Codigo::InvalidArgument,
            "o caminho nao e de um arquivo do armazem",
        ));
    };
    if com_o_armazem(|a| a.tipo(&relativo)) == Some(Tipo::Diretorio) {
        return Err(recusa_fora_da_tabela(
            &normal,
            Codigo::InvalidArgument,
            "o caminho e um diretorio",
        ));
    }
    let Some(titular) = titular() else {
        return Err(recusa_fora_da_tabela(
            &normal,
            Codigo::DenyLease,
            "quem pediu nao tem titular de arrendamento",
        ));
    };
    crate::coordenacao::tomar_por(
        &crate::coordenacao::recurso_do_caminho(&normal),
        titular,
        prazo_ms,
        "fs.claim",
    )
    .map_err(|c| (c, "outro titular tem o arrendamento"))
}

/// Solta o arrendamento de um caminho do armazém, se for de quem pede.
pub fn soltar(caminho: &str) -> Result<(), (Codigo, &'static str)> {
    let Some((normal, _)) = relativo(caminho) else {
        return Err(recusa_fora_da_tabela(
            caminho,
            Codigo::InvalidArgument,
            "o caminho nao e de um arquivo do armazem",
        ));
    };
    let Some(titular) = titular() else {
        return Err(recusa_fora_da_tabela(
            &normal,
            Codigo::DenyLease,
            "quem pediu nao tem titular de arrendamento",
        ));
    };
    crate::coordenacao::soltar_por(
        &crate::coordenacao::recurso_do_caminho(&normal),
        titular,
        "fs.release",
    )
    .map_err(|c| (c, "o arrendamento nao e seu"))
}

/// O armazém como sistema de arquivos, para o VFS: só leitura — a escrita
/// é a dos comandos, acima.
///
/// Os nós: um arquivo é a versão dele; um diretório, o número dele com o
/// bit de cima ligado — as versões cabem em 63 bits, e os dois espaços não
/// se cruzam.
struct NoVfs;

const DIRETORIO: u64 = 1 << 63;

fn no_do_diretorio(a: &Armazem, relativo: &str) -> Option<No> {
    a.id_do_diretorio(relativo).map(|id| No {
        tipo: vfs::Tipo::Diretorio,
        id: DIRETORIO | id,
        tamanho: 0,
    })
}

impl SistemaDeArquivos for NoVfs {
    fn raiz(&self) -> No {
        No {
            tipo: vfs::Tipo::Diretorio,
            id: DIRETORIO,
            tamanho: 0,
        }
    }

    fn procurar(&self, dir: &No, nome: &str) -> Result<No, vfs::Erro> {
        if dir.id & DIRETORIO == 0 {
            return Err(vfs::Erro::NaoEhDiretorio);
        }
        if !::armazem::componente_valido(nome) {
            return Err(vfs::Erro::NaoEncontrado);
        }
        com_o_armazem(|a| {
            // Um diretório que deixou de existir entre dois passos da
            // resolução não acha mais nada.
            let pai = a
                .diretorio(dir.id & !DIRETORIO)
                .ok_or(vfs::Erro::NaoEncontrado)?;
            let c = if pai.is_empty() {
                String::from(nome)
            } else {
                format!("{pai}/{nome}")
            };
            match a.tipo(&c) {
                Some(Tipo::Arquivo) => {
                    let o = a.objeto(&c).ok_or(vfs::Erro::NaoEncontrado)?;
                    Ok(No {
                        tipo: vfs::Tipo::Arquivo,
                        id: o.versao(),
                        tamanho: o.dados().len() as u64,
                    })
                }
                Some(Tipo::Diretorio) => no_do_diretorio(a, &c).ok_or(vfs::Erro::NaoEncontrado),
                None => Err(vfs::Erro::NaoEncontrado),
            }
        })
    }

    fn ler(&self, no: &No, deslocamento: u64, destino: &mut [u8]) -> Result<usize, vfs::Erro> {
        com_o_armazem(|a| {
            let (_, o) = a.por_versao(no.id).ok_or(vfs::Erro::Mudou)?;
            let dados = o.dados();
            let de = usize::try_from(deslocamento)
                .unwrap_or(usize::MAX)
                .min(dados.len());
            let n = destino.len().min(dados.len() - de);
            destino[..n].copy_from_slice(&dados[de..de + n]);
            Ok(n)
        })
    }

    fn listar(&self, dir: &No, indice: usize) -> Result<Option<Entrada>, vfs::Erro> {
        com_o_armazem(|a| {
            let d = a
                .diretorio(dir.id & !DIRETORIO)
                .ok_or(vfs::Erro::NaoEncontrado)?;
            Ok(a.filhos(d)
                .into_iter()
                .nth(indice)
                .map(|(nome, tipo)| Entrada {
                    nome,
                    tipo: match tipo {
                        Tipo::Arquivo => vfs::Tipo::Arquivo,
                        Tipo::Diretorio => vfs::Tipo::Diretorio,
                    },
                }))
        })
    }
}

/// Só para a suíte: troca o armazém em memória por `outro`, e devolve o
/// que estava — o journal não muda. O caso da reposição troca por um vazio,
/// reaplica o journal nele, compara com o que devolveu e o põe de volta.
#[cfg(feature = "modo-teste")]
pub fn trocar_de_teste(outro: Armazem) -> Armazem {
    com_o_armazem_mut(|a| core::mem::replace(a, outro))
}

/// Destrava o armazém à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ARMAZEM.force_unlock();
    }
}
