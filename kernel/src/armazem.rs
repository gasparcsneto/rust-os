//! O armazém no kernel: a árvore gravável, montada em `/armazem`.
//!
//! A conta — caminhos, diretórios, versões, donos, cotas, lotes — é a do
//! pacote `armazem`; o disco é o do volume ([`crate::volume`]); aqui eles
//! encontram o resto, e cada coisa no seu lugar, como
//! `docs/ARMAZENAMENTO.md` as separa:
//!
//! | conceito | onde |
//! |---|---|
//! | autorização e alcance de caminho | o gate, antes do handler: `fs.write` (ou `fs.read`) no papel ∩ manifesto, sobre **cada** caminho do pedido — o de um rename, os dois; o de um lote, todos |
//! | reconfirmação | no ponto de commit, com a ordem das gravações na mão: a autoridade ainda vale? — ver [`crate::autorizacao::reconfirmar`] |
//! | arrendamento | [`crate::coordenacao`], recurso `fs:<caminho>` — só o arrendamento |
//! | versão | o armazém: a versão do nó, de um contador do armazém inteiro |
//! | cota | o armazém, com a cota que a política dá ao papel de quem pede, contada por dono |
//! | persistência | o volume e o journal de estado: o ponto de commit é o registro de estado que confirma o do armazém |
//! | auditoria | a decisão do gate, e o que o comando fez, no mesmo registro do journal de estado que a confirmação |
//!
//! Este módulo não decide quem pode: chega aqui só o que o gate já
//! autorizou, e ele não tem exceção para ninguém — nem para o `sistema`,
//! que não arrenda, e por isso só muda um nó livre. E não muda nada fora do
//! que o gate decidiu: cada caminho de cada operação tem de ser um dos
//! recursos da decisão ([`crate::autorizacao::recurso_decidido`]).
//!
//! # A ordem de um lote
//!
//! Tudo com a ordem das gravações na mão ([`crate::persistencia::em_ordem`]),
//! do começo ao fim, para nada mudar entre o que se conferiu e o que se
//! gravou — e para dois lotes nunca se conferirem ao mesmo tempo:
//!
//! 1. a persistência e o volume estão disponíveis? — senão `ERROR`;
//! 2. a autoridade de quem pediu ainda vale — a sessão, a credencial, o
//!    papel, a política de agora? — senão a recusa do gate, e nada muda;
//! 3. os arrendamentos: o de outro titular, em qualquer caminho tocado —
//!    num rename, em qualquer caminho abaixo da origem ou do destino —,
//!    recusa (`CONFLICT`);
//! 4. o conteúdo novo vai para blocos livres do volume;
//! 5. o armazém prepara o lote inteiro — versões, lugares, tipos, a cota de
//!    quem pede, o teto dos metadados —, sem aplicá-lo;
//! 6. a auditoria registra o que o comando vai fazer, em nome de quem o gate
//!    autorizou, com o número da decisão;
//! 7. o volume grava o registro do lote; o journal de estado grava a
//!    confirmação, com o registro da auditoria — **o ponto de commit**;
//! 8. só então o lote vale em memória, e os blocos que ele não usa mais
//!    voltam a ser livres.
//!
//! Cada recusa depois do gate também vai para a auditoria, como o resultado
//! do comando autorizado.
//!
//! # Os rascunhos: conteúdo grande, fora do JSON
//!
//! Um pedido leva no máximo um anexo de [`crate::autorizacao::MAIOR_ANEXO`]
//! bytes. Um arquivo maior se escreve num **rascunho**: `fs.draft`, com o
//! anexo, acrescenta ao rascunho — os blocos vão para o volume na hora, e
//! contam na cota de quem escreve —, e `fs.write` com o `draft` o grava
//! inteiro, num lote só, como qualquer conteúdo. Um rascunho é de um dono e
//! de um caminho — o que o gate decidiu ao criá-lo —, e some sozinho depois
//! de [`PRAZO_DO_RASCUNHO_MS`] sem uso.
//!
//! # A leitura
//!
//! Pelo VFS, como qualquer arquivo: `fs.read`, `fs.list` e o `abrir` dos
//! processos, cada um pelo gate de sempre. O conteúdo vem do volume, bloco
//! a bloco, sem passar inteiro pela memória. O nó de um arquivo é a versão
//! dele: um descritor aberto num conteúdo que mudou recebe
//! [`crate::vfs::Erro::Mudou`], e nunca metade de um conteúdo e metade de
//! outro.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ::armazem::bloco::{CARGA, TAM_BLOCO};
use ::armazem::{Armazem, Conteudo, Cota, Extensao, Faixas, Op, Recusa, Tipo};
use politica::Codigo;
use politica::arrendamento::{Arrendamento, Titular};

use crate::trava::Mutex;
use crate::vfs::{self, Entrada, No, SistemaDeArquivos};

/// Onde o armazém está montado.
pub const RAIZ: &str = "/armazem";

/// O que a memória do kernel dá aos metadados do armazém: um oitavo do
/// heap. O conteúdo não conta — está no volume.
pub const TETO_DE_METADADOS: usize = crate::heap::HEAP_TAMANHO / 8;

/// Quantos rascunhos vivem ao mesmo tempo, no sistema e por dono.
pub const MAIS_RASCUNHOS: usize = 16;
pub const MAIS_RASCUNHOS_POR_DONO: usize = 4;
/// Um rascunho sem uso por este tempo sai, com os blocos dele.
pub const PRAZO_DO_RASCUNHO_MS: u64 = 5 * 60 * 1000;

static ARMAZEM: Mutex<Armazem> = Mutex::new(Armazem::novo());

/// Roda `f` com o armazém. Curto: o que for longo — o disco — se faz fora.
pub fn com_o_armazem<R>(f: impl FnOnce(&Armazem) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&ARMAZEM.lock()))
}

fn com_o_armazem_mut<R>(f: impl FnOnce(&mut Armazem) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ARMAZEM.lock()))
}

/// Troca o armazém em memória por `outro`, e devolve o que estava — o
/// volume, ao reabrir; a suíte, ao voltar à imagem.
///
/// Os rascunhos saem junto: os blocos deles são reservas no mapa do volume
/// de antes, e o armazém novo vem com um mapa refeito dos metadados, que
/// não as conhece. Um rascunho que ficasse soltaria, ao ser descartado,
/// blocos que o mapa novo talvez já tenha dado a um arquivo.
pub(crate) fn trocar(outro: Armazem) -> Armazem {
    drop(com_rascunhos(core::mem::take));
    com_o_armazem_mut(|a| core::mem::replace(a, outro))
}

/// Monta o armazém em [`RAIZ`]. No boot, antes de o volume repô-lo.
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

/// De onde vem o conteúdo de uma gravação.
#[derive(Clone, Copy, Debug)]
pub enum Fonte<'a> {
    /// Estes bytes — o texto do pedido, ou o anexo dele.
    Bytes(&'a [u8]),
    /// O rascunho deste número, inteiro.
    Rascunho(u64),
}

/// Uma operação pedida, com os caminhos como o pedido os trouxe.
#[derive(Clone, Copy, Debug)]
pub enum Pedido<'a> {
    /// Cria (`esperada` 0) ou substitui o conteúdo inteiro.
    Gravar {
        caminho: &'a str,
        esperada: u64,
        fonte: Fonte<'a>,
    },
    /// Acrescenta ao fim de um arquivo que existe.
    Acrescentar {
        caminho: &'a str,
        esperada: u64,
        mais: &'a [u8],
    },
    /// Apaga um arquivo que existe.
    Apagar { caminho: &'a str, esperada: u64 },
    /// Cria um diretório.
    CriarDiretorio { caminho: &'a str },
    /// Remove um diretório vazio.
    RemoverDiretorio { caminho: &'a str, esperada: u64 },
    /// Move um nó — um diretório, com tudo abaixo.
    Renomear {
        de: &'a str,
        para: &'a str,
        esperada: u64,
    },
}

impl Pedido<'_> {
    fn caminhos(&self) -> impl Iterator<Item = &str> {
        let (a, b) = match *self {
            Pedido::Gravar { caminho, .. }
            | Pedido::Acrescentar { caminho, .. }
            | Pedido::Apagar { caminho, .. }
            | Pedido::CriarDiretorio { caminho }
            | Pedido::RemoverDiretorio { caminho, .. } => (caminho, None),
            Pedido::Renomear { de, para, .. } => (de, Some(para)),
        };
        core::iter::once(a).chain(b)
    }
}

/// O que uma operação fez: a versão que o nó do destino passou a ter, e o
/// tamanho dele — zero, apagado ou diretório.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feita {
    pub versao: u64,
    pub tamanho: u64,
}

/// Por que uma mutação autorizada não aconteceu. Cada uma é de um conceito
/// só, com o código dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O caminho não é de um nó do armazém, ou não é um que o gate decidiu.
    Caminho(&'static str),
    /// A persistência ou o volume não estão disponíveis, ou a gravação
    /// falhou.
    Persistencia(&'static str),
    /// A autoridade que o gate decidiu não vale mais no ponto de commit.
    Revogada(Codigo, &'static str),
    /// Outro titular tem o arrendamento.
    Arrendamento(Titular),
    /// A versão esperada não é a de agora.
    Versao { atual: u64 },
    /// O armazém recusou: o lugar, o tipo, a cota, um teto.
    Armazem(Recusa),
    /// O rascunho não existe, não é de quem pede, ou é de outro caminho.
    Rascunho(&'static str),
    /// Não há o registro da auditoria do comando — chamada fora de um
    /// comando autorizado.
    SemAuditoria,
}

impl Falha {
    /// O código, como a auditoria e a resposta o dizem.
    pub fn codigo(self) -> Codigo {
        match self {
            Falha::Caminho(_) | Falha::Rascunho(_) => Codigo::InvalidArgument,
            Falha::Persistencia(_) | Falha::SemAuditoria => Codigo::Error,
            Falha::Revogada(c, _) => c,
            Falha::Arrendamento(_) | Falha::Versao { .. } => Codigo::Conflict,
            Falha::Armazem(Recusa::Cheio) => Codigo::Error,
            Falha::Armazem(Recusa::Cota) => Codigo::DenyQuota,
            Falha::Armazem(_) => Codigo::InvalidArgument,
        }
    }

    /// O motivo, em palavras.
    pub fn motivo(self) -> &'static str {
        match self {
            Falha::Caminho(m) | Falha::Persistencia(m) | Falha::Rascunho(m) => m,
            Falha::Revogada(_, m) => m,
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
fn recusada(recurso: &str, f: Falha) -> Falha {
    let detalhe = match f {
        Falha::Versao { atual } => format!("{}; versao atual {atual}", f.motivo()),
        _ => String::from(f.motivo()),
    };
    crate::autorizacao::auditar_execucao(recurso, f.codigo(), &detalhe);
    f
}

/// Um caminho do pedido, conferido: do armazém, e decidido pelo gate.
fn conferido(caminho: &str) -> Result<(String, String), Falha> {
    let (normal, relativo) =
        relativo(caminho).ok_or(Falha::Caminho("o caminho nao e de um no do armazem"))?;
    if !crate::autorizacao::recurso_decidido(&normal) {
        return Err(Falha::Caminho("o caminho nao e um dos que o gate decidiu"));
    }
    Ok((normal, relativo))
}

/// Faz um lote pedido pelo comando em execução neste fio: tudo ou nada.
/// Ver a ordem no topo do módulo. Na recusa, devolve qual operação recusou.
pub fn mudar(pedidos: &[Pedido]) -> Result<Vec<Feita>, (usize, Falha)> {
    let recurso_do_lote = pedidos
        .first()
        .and_then(|p| p.caminhos().next())
        .unwrap_or(RAIZ);
    // Os caminhos, antes de tudo: fora do armazém, ou fora do que o gate
    // decidiu, nada começa.
    let mut normais: Vec<Vec<(String, String)>> = Vec::with_capacity(pedidos.len());
    for (i, p) in pedidos.iter().enumerate() {
        let mut v = Vec::new();
        for c in p.caminhos() {
            match conferido(c) {
                Ok(n) => v.push(n),
                Err(f) => return Err((i, recusada(c, f))),
            }
        }
        normais.push(v);
    }
    if pedidos.is_empty() {
        return Err((0, recusada(RAIZ, Falha::Caminho("lote vazio"))));
    }
    let titular = titular();
    let Some(dono) = crate::autorizacao::dono_no_armazem() else {
        return Err((
            0,
            recusada(
                recurso_do_lote,
                Falha::Caminho("quem pediu nao tem dono no armazem"),
            ),
        ));
    };
    crate::persistencia::em_ordem(|| {
        mudar_em_ordem(pedidos, &normais, titular, &dono, recurso_do_lote)
    })
}

fn mudar_em_ordem(
    pedidos: &[Pedido],
    normais: &[Vec<(String, String)>],
    titular: Option<Titular>,
    dono: &str,
    recurso_do_lote: &str,
) -> Result<Vec<Feita>, (usize, Falha)> {
    let falhou = |i: usize, f: Falha| (i, recusada(recurso_do_lote, f));
    // Na suíte: o que acontece entre a decisão do gate e o commit — uma
    // revogação, uma política nova —, com a ordem já na mão.
    #[cfg(feature = "modo-teste")]
    if let Some(f) = crate::arch::sem_interrupcoes(|| *ANTES_DO_COMMIT.lock()) {
        f();
    }
    if let Err(m) = crate::persistencia::exigir().and_then(|()| crate::volume::exigir()) {
        return Err(falhou(0, Falha::Persistencia(m)));
    }
    // A decisão em curso: o gate decidiu antes de a ordem estar na mão, e
    // uma revogação pode ter passado por ela no meio. Aqui, com a ordem, a
    // autoridade é decidida de novo, pela política de agora — as
    // revogações gravam com a mesma ordem, então ou esta vê a revogação,
    // ou a revogação vem depois deste lote inteiro.
    if let Err((c, m)) = crate::autorizacao::reconfirmar() {
        return Err(falhou(0, Falha::Revogada(c, m)));
    }
    let cota = crate::autorizacao::cota_no_armazem();
    // Os arrendamentos de cada caminho tocado — num rename, de tudo abaixo
    // da origem e do destino.
    for (i, (p, ns)) in pedidos.iter().zip(normais).enumerate() {
        for (normal, _) in ns {
            let abaixo = matches!(p, Pedido::Renomear { .. });
            if let Err(r) = conferir_arrendamentos(normal, titular, abaixo) {
                return Err(falhou(i, r));
            }
        }
    }
    sumir_rascunhos_vencidos();
    // O conteúdo, nos blocos — e as operações para o armazém conferir.
    let mut reservadas: Faixas = Vec::new();
    let mut rascunhos: Vec<u64> = Vec::new();
    let mut ops: Vec<Op> = Vec::with_capacity(pedidos.len());
    let preparadas = (|| {
        for (i, (p, ns)) in pedidos.iter().zip(normais).enumerate() {
            let rel = |k: usize| ns[k].1.clone();
            let op = match *p {
                Pedido::Gravar {
                    esperada, fonte, ..
                } => {
                    let conteudo = match fonte {
                        Fonte::Bytes(b) => escrever_novo(b, &mut reservadas),
                        Fonte::Rascunho(id) => {
                            rascunhos.push(id);
                            fechar_rascunho(id, dono, &ns[0].0, &mut reservadas)
                        }
                    }
                    .map_err(|f| (i, f))?;
                    Op::Gravar {
                        caminho: rel(0),
                        esperada,
                        conteudo,
                    }
                }
                Pedido::Acrescentar { esperada, mais, .. } => {
                    let conteudo = acrescentar(&ns[0].1, esperada, mais, &ops, &mut reservadas)
                        .map_err(|f| (i, f))?;
                    Op::Gravar {
                        caminho: rel(0),
                        esperada,
                        conteudo,
                    }
                }
                Pedido::Apagar { esperada, .. } => Op::Apagar {
                    caminho: rel(0),
                    esperada,
                },
                Pedido::CriarDiretorio { .. } => Op::CriarDiretorio { caminho: rel(0) },
                Pedido::RemoverDiretorio { esperada, .. } => Op::RemoverDiretorio {
                    caminho: rel(0),
                    esperada,
                },
                Pedido::Renomear { esperada, .. } => Op::Renomear {
                    de: rel(0),
                    para: rel(1),
                    esperada,
                },
            };
            ops.push(op);
        }
        let reservado = reservado_em_rascunhos(dono, &rascunhos);
        com_o_armazem(|a| a.preparar(&ops, dono, cota, reservado, TETO_DE_METADADOS))
            .map_err(|(i, r)| (i, Falha::from(r)))
    })();
    // As faixas dos rascunhos continuam deles até o lote valer.
    let proprias = |reservadas: &Faixas| -> Faixas {
        let dos_rascunhos = faixas_dos_rascunhos(&rascunhos);
        ::armazem::subtrair(&::armazem::normalizar(reservadas.clone()), &dos_rascunhos)
    };
    let lote = match preparadas {
        Ok(l) => l,
        Err((i, f)) => {
            crate::volume::soltar(&proprias(&reservadas));
            return Err(falhou(i, f));
        }
    };
    // O que o comando vai fazer, em nome de quem o gate autorizou: este
    // registro vai no mesmo registro do journal de estado que a
    // confirmação, e a decisão, antes dele na cadeia, nunca depois.
    let primeira = com_o_armazem(|a| a.proxima());
    let execucao = crate::autorizacao::auditar_execucao(
        recurso_do_lote,
        Codigo::Allow,
        &format!(
            "lote a gravar: {} operacoes, versoes {}..{}",
            pedidos.len(),
            primeira,
            lote.proxima
        ),
    );
    if execucao == 0 {
        crate::volume::soltar(&proprias(&reservadas));
        return Err((0, Falha::SemAuditoria));
    }
    let escrito = match crate::volume::escrever_lote(&lote) {
        Ok(e) => e,
        Err(m) => {
            crate::volume::soltar(&proprias(&reservadas));
            return Err(falhou(0, Falha::Persistencia(m)));
        }
    };
    // O ponto de commit.
    if let Err(m) = crate::persistencia::confirmar_armazem(&escrito.confirmado, execucao) {
        // Pode ter chegado ao disco: os blocos ficam reservados até o boot,
        // que decide pelo que o journal de estado tem.
        crate::volume::nao_confirmado();
        return Err(falhou(0, Falha::Persistencia(m)));
    }
    crate::volume::confirmar(escrito);
    // Confirmado. Com a ordem na mão nada mais mudou o armazém desde a
    // preparação, e a aplicação não recusa; se recusasse, o disco teria o
    // que a memória não tem, e o boot seguinte o repõe.
    let aplicado = com_o_armazem_mut(|a| {
        a.aplicar(&lote).map(|saidas| {
            let em_uso = a.blocos_em_uso();
            let mut soltar = saidas;
            soltar.extend(::armazem::subtrair(
                &::armazem::normalizar(reservadas.clone()),
                &em_uso,
            ));
            ::armazem::normalizar(soltar)
        })
    });
    // Os rascunhos gravados deixam de existir: os blocos são de arquivos.
    tirar_rascunhos(&rascunhos);
    match aplicado {
        Ok(soltar) => crate::volume::soltar(&soltar),
        Err(r) => {
            crate::log_error!(
                "armazem",
                "o lote confirmado nao se aplicou em memoria: {}",
                r.motivo()
            );
            return Err(falhou(0, Falha::Armazem(r)));
        }
    }
    // O que cada operação fez: a versão e o tamanho do destino.
    Ok(com_o_armazem(|a| {
        pedidos
            .iter()
            .zip(normais)
            .map(|(p, ns)| {
                let alvo = match p {
                    Pedido::Renomear { .. } => &ns[1].1,
                    _ => &ns[0].1,
                };
                Feita {
                    versao: a.versao(alvo),
                    tamanho: a.no(alvo).map_or(0, ::armazem::No::tamanho),
                }
            })
            .collect()
    }))
}

/// Confere os arrendamentos de `normal` — e, com `abaixo`, de tudo abaixo
/// dele: o de outro titular recusa.
fn conferir_arrendamentos(
    normal: &str,
    titular: Option<Titular>,
    abaixo: bool,
) -> Result<(), Falha> {
    let mut recursos = alloc::vec![crate::coordenacao::recurso_do_caminho(normal)];
    if abaixo {
        recursos.extend(crate::coordenacao::arrendados_abaixo(normal));
    }
    for r in recursos {
        if let Err(e) = crate::coordenacao::conferir(&r, titular) {
            return Err(match e {
                politica::arrendamento::Recusa::Ocupado(t) => Falha::Arrendamento(t),
                outra => Falha::Persistencia(outra.motivo()),
            });
        }
    }
    Ok(())
}

/// Escreve `dados` em blocos novos, e devolve o conteúdo que os aponta. As
/// faixas reservadas vão para `reservadas`.
fn escrever_novo(dados: &[u8], reservadas: &mut Faixas) -> Result<Conteudo, Falha> {
    let blocos = (dados.len() as u64).div_ceil(CARGA as u64);
    let id = crate::volume::novo_id().map_err(Falha::Persistencia)?;
    let faixas = crate::volume::reservar(blocos).map_err(Falha::Persistencia)?;
    reservadas.extend(faixas.iter().copied());
    crate::volume::escrever_blocos(&faixas, &id, 0, dados).map_err(Falha::Persistencia)?;
    Ok(conteudo_de(&faixas, id, 0, dados.len() as u64))
}

/// O conteúdo de `tamanho` bytes cujos blocos lógicos a partir de `indice`
/// estão nas `faixas`, escritos com `id`.
fn conteudo_de(faixas: &Faixas, id: [u8; 16], indice: u64, tamanho: u64) -> Conteudo {
    let mut k = indice;
    let extensoes = faixas
        .iter()
        .map(|&(de, ate)| {
            let e = Extensao {
                bloco: de,
                quantos: (ate - de) as u32,
                id,
                indice: k,
            };
            k += ate - de;
            e
        })
        .collect();
    Conteudo { tamanho, extensoes }
}

/// O conteúdo de um acréscimo: os blocos cheios de antes ficam, o último —
/// se não estava cheio — é reescrito com o que se acrescenta, noutro lugar,
/// e o resto vai em blocos novos. Nada do que o arquivo tem é sobrescrito.
///
/// `antes` são as operações do mesmo lote que já vieram: um acréscimo
/// depois de uma gravação do mesmo arquivo, no mesmo lote, parte do
/// conteúdo daquela gravação.
fn acrescentar(
    relativo: &str,
    esperada: u64,
    mais: &[u8],
    antes: &[Op],
    reservadas: &mut Faixas,
) -> Result<Conteudo, Falha> {
    let do_lote = antes.iter().rev().find_map(|op| match op {
        Op::Gravar {
            caminho, conteudo, ..
        } if caminho == relativo => Some(conteudo.clone()),
        _ => None,
    });
    let velho = match do_lote {
        Some(c) => c,
        None => com_o_armazem(|a| match a.no(relativo) {
            Some(n) if n.versao() != esperada => Err(Falha::Versao { atual: n.versao() }),
            Some(::armazem::No::Arquivo { conteudo, .. }) => Ok(conteudo.clone()),
            Some(_) => Err(Falha::Armazem(Recusa::EhDiretorio)),
            None => Err(Falha::Armazem(Recusa::NaoExiste)),
        })?,
    };
    let carga = CARGA as u64;
    let cheios = velho.tamanho / carga;
    let sobra = (velho.tamanho % carga) as usize;
    // O pedaço do último bloco, se ele não estava cheio: lido e aberto.
    let mut cauda: Vec<u8> = Vec::with_capacity(sobra + mais.len());
    if sobra > 0 {
        let (b, id) = velho
            .onde(cheios)
            .ok_or(Falha::Armazem(Recusa::ConteudoIncoerente))?;
        let mut buf: Box<[u8; TAM_BLOCO]> = Box::new([0; TAM_BLOCO]);
        crate::volume::ler_bloco(b, &id, cheios, &mut buf).map_err(Falha::Persistencia)?;
        cauda.extend_from_slice(&buf[..sobra]);
        politica::sigiloso::zerar(&mut buf[..]);
    }
    cauda.extend_from_slice(mais);
    let blocos = (cauda.len() as u64).div_ceil(carga);
    let id = crate::volume::novo_id().map_err(Falha::Persistencia)?;
    let faixas = crate::volume::reservar(blocos).map_err(Falha::Persistencia)?;
    reservadas.extend(faixas.iter().copied());
    let escrito = crate::volume::escrever_blocos(&faixas, &id, cheios, &cauda);
    politica::sigiloso::zerar_bloco(&mut cauda);
    escrito.map_err(Falha::Persistencia)?;
    // As extensões de antes, cortadas nos blocos cheios.
    let mut extensoes: Vec<Extensao> = Vec::new();
    for e in &velho.extensoes {
        if e.indice >= cheios {
            break;
        }
        let quantos = (cheios - e.indice).min(u64::from(e.quantos)) as u32;
        extensoes.push(Extensao { quantos, ..*e });
    }
    let novo = conteudo_de(&faixas, id, cheios, 0);
    extensoes.extend(novo.extensoes);
    Ok(Conteudo {
        tamanho: velho.tamanho + mais.len() as u64,
        extensoes,
    })
}

/// Um rascunho: o conteúdo que um dono escreve aos pedaços, para um
/// caminho, antes de gravá-lo.
struct Rascunho {
    numero: u64,
    dono: String,
    /// O caminho, na forma normal: o que o gate decidiu ao criá-lo.
    caminho: String,
    id: [u8; 16],
    /// Os blocos cheios já escritos, em ordem.
    faixas: Faixas,
    blocos: u64,
    /// O que não encheu um bloco: fica na memória até o próximo pedaço, ou
    /// até a gravação.
    cauda: Vec<u8>,
    ultimo_uso_ms: u64,
}

impl Rascunho {
    fn tamanho(&self) -> u64 {
        self.blocos * CARGA as u64 + self.cauda.len() as u64
    }
}

impl Drop for Rascunho {
    fn drop(&mut self) {
        politica::sigiloso::zerar_bloco(&mut self.cauda);
    }
}

static RASCUNHOS: Mutex<Vec<Rascunho>> = Mutex::new(Vec::new());
static PROXIMO_RASCUNHO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn com_rascunhos<R>(f: impl FnOnce(&mut Vec<Rascunho>) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut RASCUNHOS.lock()))
}

/// O que os rascunhos de `dono` ocupam — fora os de `exceto`, que o lote
/// em curso já conta como conteúdo.
fn reservado_em_rascunhos(dono: &str, exceto: &[u64]) -> u64 {
    com_rascunhos(|v| {
        v.iter()
            .filter(|r| r.dono == dono && !exceto.contains(&r.numero))
            .map(Rascunho::tamanho)
            .sum()
    })
}

fn faixas_dos_rascunhos(numeros: &[u64]) -> Faixas {
    com_rascunhos(|v| {
        ::armazem::normalizar(
            v.iter()
                .filter(|r| numeros.contains(&r.numero))
                .flat_map(|r| r.faixas.iter().copied())
                .collect(),
        )
    })
}

fn tirar_rascunhos(numeros: &[u64]) {
    com_rascunhos(|v| v.retain(|r| !numeros.contains(&r.numero)));
}

/// Os rascunhos vencidos saem, com os blocos deles.
fn sumir_rascunhos_vencidos() {
    sumir_rascunhos_vencidos_em(crate::tempo::uptime_ms());
}

/// Os rascunhos vencidos em `agora` saem, com os blocos deles.
fn sumir_rascunhos_vencidos_em(agora: u64) {
    let vencidos: Vec<Rascunho> = com_rascunhos(|v| {
        let (fora, ficam): (Vec<_>, Vec<_>) = core::mem::take(v)
            .into_iter()
            .partition(|r| agora.saturating_sub(r.ultimo_uso_ms) > PRAZO_DO_RASCUNHO_MS);
        *v = ficam;
        fora
    });
    for r in vencidos {
        crate::volume::soltar(&::armazem::normalizar(r.faixas.clone()));
    }
}

/// Fecha o rascunho `numero` para gravá-lo em `normal`: escreve a cauda no
/// último bloco e devolve o conteúdo inteiro. O rascunho continua dele até
/// o lote valer.
fn fechar_rascunho(
    numero: u64,
    dono: &str,
    normal: &str,
    reservadas: &mut Faixas,
) -> Result<Conteudo, Falha> {
    let (id, faixas, blocos, cauda) = com_rascunhos(|v| {
        let r = v
            .iter_mut()
            .find(|r| r.numero == numero)
            .ok_or(Falha::Rascunho("nao ha esse rascunho"))?;
        if r.dono != dono {
            return Err(Falha::Rascunho("o rascunho e de outro dono"));
        }
        if r.caminho != normal {
            return Err(Falha::Rascunho("o rascunho e de outro caminho"));
        }
        Ok((r.id, r.faixas.clone(), r.blocos, r.cauda.clone()))
    })?;
    reservadas.extend(faixas.iter().copied());
    let mut conteudo = conteudo_de(&faixas, id, 0, blocos * CARGA as u64);
    if !cauda.is_empty() {
        let ultima = crate::volume::reservar(1).map_err(Falha::Persistencia)?;
        reservadas.extend(ultima.iter().copied());
        crate::volume::escrever_blocos(&ultima, &id, blocos, &cauda)
            .map_err(Falha::Persistencia)?;
        conteudo
            .extensoes
            .extend(conteudo_de(&ultima, id, blocos, 0).extensoes);
        conteudo.tamanho += cauda.len() as u64;
    }
    Ok(conteudo)
}

/// `fs.draft`: acrescenta `dados` ao rascunho `numero` — ou cria um, com
/// `None` — para o caminho `caminho`, que o gate decidiu. Devolve o número
/// e o tamanho. Os blocos cheios vão para o volume já; a cota de quem
/// escreve conta o rascunho inteiro.
pub fn rascunho(caminho: &str, numero: Option<u64>, dados: &[u8]) -> Result<(u64, u64), Falha> {
    let (normal, _) = conferido(caminho).map_err(|f| recusada(caminho, f))?;
    let Some(dono) = crate::autorizacao::dono_no_armazem() else {
        return Err(recusada(
            &normal,
            Falha::Caminho("quem pediu nao tem dono no armazem"),
        ));
    };
    crate::persistencia::em_ordem(|| rascunho_em_ordem(&normal, numero, dados, &dono))
        .map_err(|f| recusada(&normal, f))
}

fn rascunho_em_ordem(
    normal: &str,
    numero: Option<u64>,
    dados: &[u8],
    dono: &str,
) -> Result<(u64, u64), Falha> {
    crate::persistencia::exigir()
        .and_then(|()| crate::volume::exigir())
        .map_err(Falha::Persistencia)?;
    if let Err((c, m)) = crate::autorizacao::reconfirmar() {
        return Err(Falha::Revogada(c, m));
    }
    sumir_rascunhos_vencidos();
    // A cota: o que o dono tem, mais os rascunhos dele, mais isto.
    let cota = crate::autorizacao::cota_no_armazem();
    let usado = com_o_armazem(|a| a.uso(dono).bytes) + reservado_em_rascunhos(dono, &[]);
    if usado.saturating_add(dados.len() as u64) > cota.bytes {
        return Err(Falha::Armazem(Recusa::Cota));
    }
    let agora = crate::tempo::uptime_ms();
    // Um novo, ou o pedido, que tem de ser deste dono e deste caminho.
    let numero = match numero {
        Some(n) => {
            com_rascunhos(|v| match v.iter().find(|r| r.numero == n) {
                None => Err(Falha::Rascunho("nao ha esse rascunho")),
                Some(r) if r.dono != dono => Err(Falha::Rascunho("o rascunho e de outro dono")),
                Some(r) if r.caminho != normal => {
                    Err(Falha::Rascunho("o rascunho e de outro caminho"))
                }
                Some(_) => Ok(()),
            })?;
            n
        }
        None => {
            let id = crate::volume::novo_id().map_err(Falha::Persistencia)?;
            let n = PROXIMO_RASCUNHO.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            com_rascunhos(|v| {
                if v.len() >= MAIS_RASCUNHOS
                    || v.iter().filter(|r| r.dono == dono).count() >= MAIS_RASCUNHOS_POR_DONO
                {
                    return Err(Falha::Rascunho("rascunhos demais abertos"));
                }
                v.push(Rascunho {
                    numero: n,
                    dono: String::from(dono),
                    caminho: String::from(normal),
                    id,
                    faixas: Vec::new(),
                    blocos: 0,
                    cauda: Vec::new(),
                    ultimo_uso_ms: agora,
                });
                Ok(())
            })?;
            n
        }
    };
    // A cauda de antes e o que chega: os blocos cheios vão para o disco.
    let (id, blocos, mut juntos) = com_rascunhos(|v| {
        let r = v
            .iter_mut()
            .find(|r| r.numero == numero)
            .expect("conferido acima");
        let mut juntos = core::mem::take(&mut r.cauda);
        juntos.extend_from_slice(dados);
        (r.id, r.blocos, juntos)
    });
    let cheios = juntos.len() / CARGA;
    let resto = juntos.split_off(cheios * CARGA);
    let escritos = (|| {
        let faixas = crate::volume::reservar(cheios as u64).map_err(Falha::Persistencia)?;
        if let Err(m) = crate::volume::escrever_blocos(&faixas, &id, blocos, &juntos) {
            crate::volume::soltar(&faixas);
            return Err(Falha::Persistencia(m));
        }
        Ok(faixas)
    })();
    politica::sigiloso::zerar_bloco(&mut juntos);
    let faixas = match escritos {
        Ok(f) => f,
        Err(f) => {
            // O rascunho perdeu o que tinha na memória: sai inteiro.
            descartar_numero(numero);
            return Err(f);
        }
    };
    let tamanho = com_rascunhos(|v| {
        let r = v
            .iter_mut()
            .find(|r| r.numero == numero)
            .expect("conferido acima");
        r.faixas.extend(faixas.iter().copied());
        r.blocos += cheios as u64;
        r.cauda = resto;
        r.ultimo_uso_ms = agora;
        r.tamanho()
    });
    Ok((numero, tamanho))
}

fn descartar_numero(numero: u64) {
    let fora: Vec<Rascunho> = com_rascunhos(|v| {
        let (fora, ficam): (Vec<_>, Vec<_>) = core::mem::take(v)
            .into_iter()
            .partition(|r| r.numero == numero);
        *v = ficam;
        fora
    });
    for r in fora {
        crate::volume::soltar(&::armazem::normalizar(r.faixas.clone()));
    }
}

/// `fs.discard`: o rascunho sai, com os blocos — só pelo dono dele.
pub fn descartar(numero: u64) -> Result<(), Falha> {
    let Some(dono) = crate::autorizacao::dono_no_armazem() else {
        return Err(Falha::Caminho("quem pediu nao tem dono no armazem"));
    };
    let caminho = com_rascunhos(|v| {
        v.iter()
            .find(|r| r.numero == numero && r.dono == dono)
            .map(|r| r.caminho.clone())
    })
    .ok_or(Falha::Rascunho("nao ha esse rascunho deste dono"))?;
    if !crate::autorizacao::recurso_decidido(&caminho) {
        return Err(recusada(
            &caminho,
            Falha::Caminho("o caminho nao e um dos que o gate decidiu"),
        ));
    }
    crate::persistencia::em_ordem(|| descartar_numero(numero));
    Ok(())
}

/// Quantos rascunhos estão abertos — para a suíte.
#[cfg(feature = "modo-teste")]
pub fn rascunhos_de_teste() -> usize {
    com_rascunhos(|v| v.len())
}

/// Só para a suíte: os rascunhos vencem agora.
#[cfg(feature = "modo-teste")]
pub fn vencer_rascunhos_de_teste() {
    crate::persistencia::em_ordem(|| sumir_rascunhos_vencidos_em(u64::MAX));
}

/// O que se sabe de um caminho: o tipo, a versão, o tamanho, o dono e o
/// arrendamento.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Situacao {
    pub tipo: Option<Tipo>,
    pub versao: u64,
    pub tamanho: u64,
    pub dono: Option<String>,
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
    let (tipo, versao, tamanho, dono) = com_o_armazem(|a| {
        (
            a.tipo(&relativo),
            a.versao(&relativo),
            a.no(&relativo).map_or(0, ::armazem::No::tamanho),
            a.no(&relativo).map(|n| String::from(n.dono())),
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
            dono,
            arrendamento,
        },
    ))
}

/// O uso e a cota de quem pede, no armazém, e os rascunhos dele.
pub fn uso_de_quem_pede() -> Option<(::armazem::Uso, Cota, u64)> {
    let dono = crate::autorizacao::dono_no_armazem()?;
    let uso = com_o_armazem(|a| a.uso(&dono));
    Some((
        uso,
        crate::autorizacao::cota_no_armazem(),
        reservado_em_rascunhos(&dono, &[]),
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
/// O caminho pode ainda não ter nó — quem vai criá-lo o arrenda antes —,
/// mas não pode ser um diretório.
pub fn arrendar(caminho: &str, prazo_ms: u64) -> Result<Arrendamento, (Codigo, &'static str)> {
    let Some((normal, relativo)) = relativo(caminho).filter(|(_, r)| ::armazem::caminho_valido(r))
    else {
        return Err(recusa_fora_da_tabela(
            caminho,
            Codigo::InvalidArgument,
            "o caminho nao e de um no do armazem",
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
            "o caminho nao e de um no do armazem",
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
/// Os nós: um arquivo é a versão dele; um diretório, a versão dele com o
/// bit de cima ligado — as versões cabem em 63 bits, e os dois espaços não
/// se cruzam. A raiz é o diretório zero.
struct NoVfs;

const DIRETORIO: u64 = 1 << 63;

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
            // Um diretório que mudou entre dois passos da resolução não acha
            // mais nada.
            let pai = match dir.id & !DIRETORIO {
                0 => String::new(),
                v => match a.por_versao(v) {
                    Some((c, n)) if n.tipo() == Tipo::Diretorio => String::from(c),
                    _ => return Err(vfs::Erro::NaoEncontrado),
                },
            };
            let c = if pai.is_empty() {
                String::from(nome)
            } else {
                format!("{pai}/{nome}")
            };
            match a.no(&c) {
                Some(n @ ::armazem::No::Arquivo { .. }) => Ok(No {
                    tipo: vfs::Tipo::Arquivo,
                    id: n.versao(),
                    tamanho: n.tamanho(),
                }),
                Some(n) => Ok(No {
                    tipo: vfs::Tipo::Diretorio,
                    id: DIRETORIO | n.versao(),
                    tamanho: 0,
                }),
                None => Err(vfs::Erro::NaoEncontrado),
            }
        })
    }

    fn ler(&self, no: &No, deslocamento: u64, destino: &mut [u8]) -> Result<usize, vfs::Erro> {
        let conteudo = com_o_armazem(|a| {
            a.por_versao(no.id)
                .and_then(|(_, n)| n.conteudo().cloned())
                .ok_or(vfs::Erro::Mudou)
        })?;
        let carga = CARGA as u64;
        let mut buf: Box<[u8; TAM_BLOCO]> = Box::new([0; TAM_BLOCO]);
        let mut feito = 0usize;
        while feito < destino.len() {
            let pos = deslocamento.saturating_add(feito as u64);
            if pos >= conteudo.tamanho {
                break;
            }
            let k = pos / carga;
            let dentro = (pos % carga) as usize;
            let (b, id) = conteudo.onde(k).ok_or(vfs::Erro::DoDispositivo)?;
            if crate::volume::ler_bloco(b, &id, k, &mut buf).is_err() {
                // Um bloco que não abre: o conteúdo mudou e o bloco foi
                // reaproveitado — ou o disco estragou.
                let mudou = com_o_armazem(|a| a.por_versao(no.id).is_none());
                politica::sigiloso::zerar(&mut buf[..]);
                return Err(if mudou {
                    vfs::Erro::Mudou
                } else {
                    vfs::Erro::DoDispositivo
                });
            }
            let n = (CARGA - dentro)
                .min(destino.len() - feito)
                .min((conteudo.tamanho - pos) as usize);
            destino[feito..feito + n].copy_from_slice(&buf[dentro..dentro + n]);
            feito += n;
        }
        politica::sigiloso::zerar(&mut buf[..]);
        // Lido inteiro com a versão ainda valendo: nenhum bloco dela foi
        // solto no meio, porque só se soltam os de uma versão que saiu.
        if com_o_armazem(|a| a.por_versao(no.id).is_none()) {
            return Err(vfs::Erro::Mudou);
        }
        Ok(feito)
    }

    fn listar(&self, dir: &No, indice: usize) -> Result<Option<Entrada>, vfs::Erro> {
        com_o_armazem(|a| {
            let d = match dir.id & !DIRETORIO {
                0 => String::new(),
                v => match a.por_versao(v) {
                    Some((c, n)) if n.tipo() == Tipo::Diretorio => String::from(c),
                    _ => return Err(vfs::Erro::NaoEncontrado),
                },
            };
            Ok(a.filhos(&d)
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

/// Só para a suíte: o que roda no começo de cada lote, com a ordem das
/// gravações na mão e antes da reconfirmação.
#[cfg(feature = "modo-teste")]
static ANTES_DO_COMMIT: Mutex<Option<fn()>> = Mutex::new(None);

/// Só para a suíte: põe (ou tira) o que roda antes do commit de cada lote.
#[cfg(feature = "modo-teste")]
pub fn antes_do_commit_de_teste(f: Option<fn()>) {
    crate::arch::sem_interrupcoes(|| *ANTES_DO_COMMIT.lock() = f);
}

/// Só para a suíte: o conteúdo do arquivo `relativo`, lido do volume pelo
/// mesmo caminho do VFS.
#[cfg(feature = "modo-teste")]
pub fn conteudo_de_teste(relativo: &str) -> Option<Vec<u8>> {
    let (versao, tamanho) = com_o_armazem(|a| {
        a.no(relativo)
            .filter(|n| n.tipo() == Tipo::Arquivo)
            .map(|n| (n.versao(), n.tamanho()))
    })?;
    let mut v = alloc::vec![0u8; tamanho as usize];
    let no = No {
        tipo: vfs::Tipo::Arquivo,
        id: versao,
        tamanho,
    };
    let n = NoVfs.ler(&no, 0, &mut v).ok()?;
    v.truncate(n);
    Some(v)
}

/// Só para a suíte: troca o armazém em memória por `outro`, e devolve o
/// que estava — o journal não muda.
#[cfg(feature = "modo-teste")]
pub fn trocar_de_teste(outro: Armazem) -> Armazem {
    trocar(outro)
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
        RASCUNHOS.force_unlock();
        #[cfg(feature = "modo-teste")]
        ANTES_DO_COMMIT.force_unlock();
    }
}
