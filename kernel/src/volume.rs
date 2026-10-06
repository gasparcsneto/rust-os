//! O volume do armazém: a partição própria onde mora o conteúdo dos
//! arquivos e o journal dos metadados deles.
//!
//! # Por que uma partição própria
//!
//! O armazém morava no journal de estado, e dividia com o estado de
//! autoridade o espaço da partição e o heap do kernel: os tetos de 16 KiB
//! por arquivo, 256 arquivos e 512 KiB no total existiam para um armazém
//! cheio não tirar o lugar de uma revogação. Aqui ele tem o lugar dele. O
//! journal de estado guarda, do armazém, uma entrada só —
//! [`diario::estado::tipo::ARMAZEM_CONFIRMADO`]: qual registro do journal
//! do armazém vale —, de tamanho fixo, e a base de uma compactação do
//! estado leva essa entrada e mais nada do armazém.
//!
//! # O que mora no volume
//!
//! ```text
//! setor 0                       setores_do_diario                 setores
//! | journal dos metadados       | área de dados: blocos de 4 KiB  |
//! | (duas regiões, como o de    | cifrados — ver armazem::bloco   |
//! |  estado)                    |                                 |
//! ```
//!
//! O journal dos metadados tem o formato do journal de estado (o pacote
//! `diario`), com uma chave própria, derivada da do Duke por outro rótulo:
//! um registro de um não abre no outro. Cada registro é um **lote** de
//! mudanças ([`armazem::Lote`]); a abertura diz a geometria do volume, e a
//! base de uma compactação leva os nós e a próxima versão.
//!
//! # A âncora do journal do armazém é o journal de estado
//!
//! O journal do armazém não fala com o TPM. Cada registro dele confirma a
//! âncora seguinte de um contador **dele**, e quem guarda o valor desse
//! contador é o journal de estado: a entrada `ARMAZEM_CONFIRMADO` diz a
//! âncora e o elo do último registro do armazém que vale. A gravação de um
//! lote é:
//!
//! 1. os blocos do conteúdo, em blocos livres — nunca por cima do que um
//!    arquivo tem;
//! 2. o registro do lote no journal do armazém, com a âncora seguinte;
//! 3. a descarga do disco — os blocos e o registro, juntos;
//! 4. o registro no journal de estado com `ARMAZEM_CONFIRMADO` (a âncora e
//!    o elo do passo 2) e a auditoria da execução do comando: escrito,
//!    descarregado, e a âncora do TPM avançada. **Este é o ponto de
//!    commit.**
//! 5. só então o lote vale em memória, e os blocos que ele deixou de usar
//!    voltam a ser livres.
//!
//! Uma queda antes do passo 4 deixa no volume blocos e um registro que o
//! journal de estado não confirma: no boot, o percurso do journal do
//! armazém para antes deles ([`diario::percorrer_ate`]), o escritor
//! continua por cima, e os blocos — que nenhum metadado aponta — estão
//! livres. Nada de um lote pela metade parece confirmado. Uma queda depois
//! do passo 4 é um lote confirmado, inteiro: o journal de estado o diz, e
//! o do armazém o tem, porque foi descarregado antes.
//!
//! Um volume devolvido a uma cópia anterior, ou trocado por outro, não
//! chega à âncora e ao elo confirmados: o armazém fica indisponível — e o
//! estado de autoridade não é afetado.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ::armazem::bloco::{self, CARGA, SETORES_POR_BLOCO, TAM_BLOCO};
use ::armazem::mapa::Mapa;
use ::armazem::registro::{self, Entrada, Volume as Geometria};
use ::armazem::{Armazem, Faixas, Lote, Mudanca};
use diario::Meio;
use diario::estado::tipo;

use crate::trava::Mutex;
use crate::virtio::blk::Janela;

/// O menor volume aceito: 8 MiB. Abaixo disso o journal dos metadados não
/// teria lugar para um lote grande e uma compactação.
pub const MENOR_EM_SETORES: u64 = 8 * 1024 * 1024 / 512;

/// Quanto do volume é do journal dos metadados: um oitavo, e ao menos
/// 2 MiB — múltiplo de um bloco.
fn setores_do_diario(setores: u64) -> u64 {
    let s = (setores / 8).max(2 * 1024 * 1024 / 512);
    s - s % SETORES_POR_BLOCO
}

/// Quantas faixas o conteúdo de uma escrita pode ocupar, no máximo: o mapa
/// procura uma faixa só, e só parte se não houver.
pub const MAIS_FAIXAS_POR_ESCRITA: usize = 64;

/// Compacta o journal dos metadados quando a região passa disto, em
/// quartos.
const COMPACTAR_A_PARTIR_DE_QUARTOS: u64 = 3;

/// O que o journal de estado confirmou do volume: a geometria e qual
/// registro do journal do armazém vale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmado {
    pub geometria: Geometria,
    pub ancora: u64,
    pub elo: [u8; 32],
}

/// O estado do volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Ainda não aberto.
    Fechado,
    /// O disco não tem a partição do armazém.
    SemParticao,
    /// Não se grava: o motivo vai junto.
    Indisponivel(&'static str),
    Disponivel,
}

impl Estado {
    pub fn motivo(self) -> &'static str {
        match self {
            Estado::Fechado => "o volume do armazem ainda nao foi aberto",
            Estado::SemParticao => "o disco nao tem a particao do armazem",
            Estado::Indisponivel(m) => m,
            Estado::Disponivel => "disponivel",
        }
    }
}

struct Volume {
    estado: Estado,
    confirmado: Option<Confirmado>,
    /// Qual das duas regiões do journal dos metadados vale.
    regiao: usize,
    /// O escritor do journal dos metadados — fora daqui só enquanto uma
    /// gravação o usa, com a ordem das gravações na mão.
    escritor: Option<diario::Escritor>,
    /// Os blocos em uso: os dos arquivos, e os reservados.
    mapa: Option<Mapa>,
}

static VOLUME: Mutex<Volume> = Mutex::new(Volume {
    estado: Estado::Fechado,
    confirmado: None,
    regiao: 0,
    escritor: None,
    mapa: None,
});

fn com<R>(f: impl FnOnce(&mut Volume) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut VOLUME.lock()))
}

/// O estado do volume.
pub fn estado() -> Estado {
    com(|v| v.estado)
}

/// O volume pode gravar? `Err` com o motivo.
pub fn exigir() -> Result<(), &'static str> {
    match estado() {
        Estado::Disponivel => Ok(()),
        outro => Err(outro.motivo()),
    }
}

/// O que o journal de estado confirmou, para a base de uma compactação dele.
pub fn confirmado() -> Option<Confirmado> {
    com(|v| v.confirmado)
}

/// Os blocos da área de dados: quantos, e quantos livres.
pub fn ocupacao() -> Option<(u64, u64)> {
    com(|v| v.mapa.as_ref().map(|m| (m.total(), m.livres())))
}

/// A chave do journal dos metadados e a dos blocos: derivadas da chave do
/// Duke, cada uma com o seu rótulo — nenhuma é a do journal de estado.
fn chaves() -> Option<([u8; 32], [u8; 32])> {
    crate::identidade::com_chave_do_duke(|k| {
        let sal = b"Duke armazem v1";
        (
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"armazem: journal dos metadados"]),
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"armazem: blocos de conteudo"]),
        )
    })
}

/// A partição do armazém: a janela de escrita que o boot fixou para ela.
fn particao() -> Result<(u64, u64), &'static str> {
    crate::virtio::blk::com_o_disco(|d| d.janela(Janela::Armazem))
        .flatten()
        .ok_or("o disco nao tem a particao do armazem")
}

/// Uma faixa do volume como meio do journal: setores relativos ao começo
/// dela.
struct NoVolume {
    primeiro: u64,
    setores: u64,
}

impl Meio for NoVolume {
    fn setores(&self) -> u64 {
        self.setores
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < destino.len() {
            let n = (destino.len() - feito).min(crate::virtio::blk::MAIOR_LEITURA);
            let s = self.primeiro + setor + (feito / diario::TAM_SETOR) as u64;
            crate::virtio::blk::com_o_disco(|d| d.ler(s, &mut destino[feito..feito + n]))
                .ok_or("nao ha disco")??;
            feito += n;
        }
        Ok(())
    }

    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < origem.len() {
            let n = (origem.len() - feito).min(crate::virtio::blk::MAIOR_LEITURA);
            let s = self.primeiro + setor + (feito / diario::TAM_SETOR) as u64;
            crate::virtio::blk::com_o_disco(|d| {
                d.gravar_setores(Janela::Armazem, s, &origem[feito..feito + n])
            })
            .ok_or("nao ha disco")??;
            feito += n;
        }
        Ok(())
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        crate::virtio::blk::com_o_disco(|d| d.descarregar_disco()).ok_or("nao ha disco")?
    }
}

/// As duas regiões do journal dos metadados de um volume com esta
/// geometria.
fn regioes(g: &Geometria) -> Result<[NoVolume; 2], &'static str> {
    let (primeiro, _) = particao()?;
    Ok(
        diario::regioes(g.setores_do_diario, None).map(|(inicio, setores)| NoVolume {
            primeiro: primeiro + inicio,
            setores,
        }),
    )
}

/// O primeiro setor (absoluto) da área de dados, e quantos blocos ela tem.
fn area_de_dados(g: &Geometria) -> Result<(u64, u64), &'static str> {
    let (primeiro, _) = particao()?;
    Ok((
        primeiro + g.setores_do_diario,
        (g.setores - g.setores_do_diario) / SETORES_POR_BLOCO,
    ))
}

fn nonce() -> Result<[u8; diario::TAM_NONCE], &'static str> {
    let mut n = [0u8; diario::TAM_NONCE];
    crate::aleatorio::preencher(&mut n).map_err(|_| "sem entropia para o nonce")?;
    Ok(n)
}

/// Um identificador novo de escrita — ver [`armazem::bloco`].
pub fn novo_id() -> Result<[u8; 16], &'static str> {
    let mut id = [0u8; 16];
    crate::aleatorio::preencher(&mut id).map_err(|_| "sem entropia para o id da escrita")?;
    Ok(id)
}

/// Confere a partição contra uma geometria: o tamanho é o mesmo — uma
/// partição redimensionada, ou trocada por outra, não é o volume que o
/// journal de estado confirmou.
fn conferir_particao(g: &Geometria) -> Result<(), &'static str> {
    let (_, setores) = particao()?;
    if setores != g.setores {
        return Err("a particao do armazem nao tem o tamanho do volume confirmado");
    }
    if g.setores_do_diario != setores_do_diario(g.setores) {
        return Err("a geometria do volume confirmado nao e a desta versao");
    }
    Ok(())
}

/// Abre o volume no boot, com o que o journal de estado confirmou — ou cria
/// um, se ele não confirmou nenhum. Chamada pela persistência, com a ordem
/// das gravações na mão e o journal de estado disponível; para criar, a
/// persistência grava a confirmação da abertura (ver
/// [`crate::persistencia::confirmar_armazem`]).
///
/// Repõe o armazém em memória a partir do journal dos metadados, até o
/// registro confirmado e só ele. Na recusa, o armazém fica vazio e o volume
/// indisponível, com o motivo — o estado de autoridade não muda.
pub fn abrir(lido: Option<Confirmado>) {
    let estado = match abrir_de_fato(lido) {
        Ok(()) => Estado::Disponivel,
        Err(m) => {
            crate::armazem::trocar(Armazem::novo());
            if particao().is_err() && lido.is_none() {
                Estado::SemParticao
            } else {
                Estado::Indisponivel(m)
            }
        }
    };
    com(|v| v.estado = estado);
    match estado {
        Estado::Disponivel => {
            let (total, livres) = ocupacao().unwrap_or((0, 0));
            crate::log_info!(
                "armazem",
                "volume aberto: ancora {}, {} nos, {} de {} blocos livres",
                confirmado().map_or(0, |c| c.ancora),
                crate::armazem::com_o_armazem(|a| a.quantos()),
                livres,
                total
            );
        }
        outro => crate::log_warn!("armazem", "volume: {}", outro.motivo()),
    }
}

/// O journal de estado não está disponível no boot: o volume também não —
/// o que o journal diz dele não se confirma.
pub fn sem_persistencia(motivo: &'static str) {
    crate::armazem::trocar(Armazem::novo());
    com(|v| {
        v.escritor = None;
        v.mapa = None;
        v.confirmado = None;
        v.estado = Estado::Indisponivel(motivo);
    });
}

fn abrir_de_fato(confirmado: Option<Confirmado>) -> Result<(), &'static str> {
    com(|v| {
        v.escritor = None;
        v.mapa = None;
        v.confirmado = None;
    });
    let (chave, _) = chaves().ok_or("sem a chave do Duke")?;
    let Some(c) = confirmado else {
        return criar(&chave);
    };
    conferir_particao(&c.geometria)?;
    let mut regs = regioes(&c.geometria)?;
    // A região que vale é a que chega exatamente ao registro confirmado:
    // a âncora e o elo. A outra é uma compactação que não foi confirmada,
    // ou a região de antes da última — nenhuma diz nada.
    let mut escolhida = None;
    for (i, r) in regs.iter_mut().enumerate() {
        let p = diario::percorrer_ate(r, &chave, c.ancora, |_| Ok::<(), ()>(()))
            .map_err(|_| "o journal do armazem nao se le")?;
        if p.inteiro() && p.ultima_ancora() == Some(c.ancora) && p.elo == c.elo {
            escolhida = Some(i);
        }
    }
    let i = escolhida.ok_or(
        "o journal do armazem nao chega ao registro confirmado: volume restaurado, trocado ou estragado",
    )?;
    let mut a = Armazem::novo();
    let mut volume_lido = None;
    let p = diario::percorrer_ate(&mut regs[i], &chave, c.ancora, |r| {
        repor(&mut a, &r, &mut volume_lido)
    })
    .map_err(|e| match e {
        diario::Interrompido::Meio(m) | diario::Interrompido::Recusado { motivo: m, .. } => m,
    })?;
    if volume_lido != Some(c.geometria) {
        return Err("o journal do armazem e de outro volume");
    }
    if !a.coerente() {
        return Err("o armazem reposto nao e coerente");
    }
    // O mapa: os blocos que os arquivos têm. Um bloco de dois arquivos, ou
    // fora da área, é um volume que não se explica.
    let (_, blocos) = area_de_dados(&c.geometria)?;
    let mut mapa = Mapa::novo(blocos);
    for (de, ate) in a.blocos_em_uso() {
        mapa.marcar(de, ate)?;
    }
    let total = regs[i].setores();
    let escritor = diario::Escritor::depois_de(&p, c.ancora, total);
    crate::armazem::trocar(a);
    com(|v| {
        v.confirmado = Some(c);
        v.regiao = i;
        v.escritor = Some(escritor);
        v.mapa = Some(mapa);
    });
    Ok(())
}

/// Repõe um registro do journal do armazém em `a`.
fn repor(
    a: &mut Armazem,
    r: &diario::Registro,
    volume: &mut Option<Geometria>,
) -> Result<(), &'static str> {
    let entradas = registro::entradas(&r.conteudo)?;
    match r.tipo {
        tipo::ABERTURA | tipo::BASE_FIM => {
            for e in entradas {
                match e {
                    Entrada::Volume(g) => *volume = Some(g),
                    _ => return Err("entrada fora do lugar na abertura do armazem"),
                }
            }
        }
        tipo::ARMAZEM => {
            let mudancas: Vec<Mudanca> = entradas
                .into_iter()
                .map(|e| match e {
                    Entrada::Mudanca(m) => Ok(m),
                    _ => Err("entrada fora do lugar num lote do armazem"),
                })
                .collect::<Result<_, _>>()?;
            a.aplicar(&Lote {
                mudancas,
                proxima: 0,
            })
            .map_err(::armazem::Recusa::motivo)?;
        }
        tipo::BASE => {
            for e in entradas {
                match e {
                    Entrada::Mudanca(Mudanca::Arquivo {
                        caminho,
                        versao,
                        conteudo,
                        dono,
                    }) => a.restaurar(
                        &caminho,
                        ::armazem::No::Arquivo {
                            versao,
                            conteudo,
                            dono,
                        },
                    ),
                    Entrada::Mudanca(Mudanca::Diretorio {
                        caminho,
                        versao,
                        dono,
                    }) => a.restaurar(&caminho, ::armazem::No::Diretorio { versao, dono }),
                    Entrada::Proxima(n) => a.fixar_proxima(n),
                    _ => return Err("entrada fora do lugar na base do armazem"),
                }
                .map_err(::armazem::Recusa::motivo)?;
            }
        }
        _ => return Err("registro de tipo desconhecido no journal do armazem"),
    }
    Ok(())
}

/// Cria o volume: a geometria, e a abertura do journal dos metadados na
/// primeira região, descarregada. A confirmação vai para o journal de
/// estado logo em seguida; sem ela, o volume não existe — e o próximo boot
/// cria outro por cima.
fn criar(chave: &[u8; 32]) -> Result<(), &'static str> {
    let (_, setores) = particao()?;
    if setores < MENOR_EM_SETORES {
        return Err("a particao do armazem e menor que o menor volume");
    }
    let g = Geometria {
        id: novo_id()?,
        setores,
        setores_do_diario: setores_do_diario(setores),
    };
    let [mut r, _] = regioes(&g)?;
    let total = r.setores();
    let mut escritor = diario::Escritor::depois_de(&diario::Percorrido::vazio(), 0, total);
    let dados = diario::estado::campos(&[&registro::volume(&g)?])?;
    let montado = escritor.montar(
        chave,
        nonce()?,
        &diario::Conteudo {
            tipo: tipo::ABERTURA,
            versao_da_politica: 0,
            tempo: crate::persistencia::agora(),
            dados: &dados,
        },
    )?;
    r.escrever(montado.setor, &montado.bytes)?;
    r.descarregar()?;
    let c = Confirmado {
        geometria: g,
        ancora: montado.ancora,
        elo: montado.elo(),
    };
    crate::persistencia::confirmar_armazem(&c, 0)?;
    escritor.confirmar(&montado, montado.ancora)?;
    let (_, blocos) = area_de_dados(&g)?;
    crate::armazem::trocar(Armazem::novo());
    com(|v| {
        v.confirmado = Some(c);
        v.regiao = 0;
        v.escritor = Some(escritor);
        v.mapa = Some(Mapa::novo(blocos));
    });
    crate::log_info!(
        "armazem",
        "volume criado: {} setores, {} do journal",
        g.setores,
        g.setores_do_diario
    );
    Ok(())
}

/// Reserva `n` blocos para uma escrita. As faixas são de quem reservou até
/// [`soltar`] — ou até um lote que as leve ser gravado.
pub fn reservar(n: u64) -> Result<Faixas, &'static str> {
    com(|v| {
        let mapa = v
            .mapa
            .as_mut()
            .ok_or("o volume do armazem nao esta aberto")?;
        mapa.reservar(n, MAIS_FAIXAS_POR_ESCRITA)
            .ok_or("o volume do armazem nao tem blocos livres para isso")
    })
}

/// Solta faixas: reservadas que não serão usadas, ou de conteúdo que saiu.
/// Um erro aqui é uma conta errada do kernel: o volume fica indisponível
/// em vez de seguir com um mapa que não confere.
pub fn soltar(faixas: &Faixas) {
    let r = com(|v| match v.mapa.as_mut() {
        Some(m) => m.soltar_faixas(faixas),
        None => Ok(()),
    });
    if let Err(m) = r {
        crate::log_error!("armazem", "o mapa de blocos nao confere: {}", m);
        com(|v| v.estado = Estado::Indisponivel("o mapa de blocos nao confere"));
    }
}

/// A geometria e as chaves para ler ou escrever blocos.
fn para_blocos() -> Result<(Geometria, [u8; 32]), &'static str> {
    let g =
        com(|v| v.confirmado.map(|c| c.geometria)).ok_or("o volume do armazem nao esta aberto")?;
    let (_, chave) = chaves().ok_or("sem a chave do Duke")?;
    Ok((g, chave))
}

/// Escreve `dados` nos blocos das `faixas`, cifrados com a escrita `id`, a
/// partir do bloco lógico `indice`. Os blocos são de quem os reservou: nada
/// mais escreve neles, e nada os lê até um lote que os leve ser gravado.
pub fn escrever_blocos(
    faixas: &Faixas,
    id: &[u8; 16],
    indice: u64,
    dados: &[u8],
) -> Result<(), &'static str> {
    let (g, chave) = para_blocos()?;
    let (inicio, blocos) = area_de_dados(&g)?;
    let mut buffer: Box<[u8; TAM_BLOCO]> = Box::new([0; TAM_BLOCO]);
    let mut pedacos = dados.chunks(CARGA);
    let mut k = indice;
    for &(de, ate) in faixas {
        if ate > blocos {
            return Err("faixa de blocos fora da area de dados");
        }
        for b in de..ate {
            let pedaco = pedacos.next().unwrap_or(&[]);
            bloco::selar(&chave, &g.id, id, k, pedaco, &mut buffer)?;
            let setor = inicio + b * SETORES_POR_BLOCO;
            crate::virtio::blk::com_o_disco(|d| {
                d.gravar_setores(Janela::Armazem, setor, &buffer[..])
            })
            .ok_or("nao ha disco")??;
            k += 1;
        }
    }
    politica::sigiloso::zerar(&mut buffer[..]);
    if pedacos.next().is_some() {
        return Err("mais dados que os blocos reservados");
    }
    Ok(())
}

/// Lê e abre o bloco `bloco` da área de dados — o pedaço `indice` da
/// escrita `id` —, em `destino`. Um bloco que não abre é `Err`: outro
/// conteúdo no lugar, ou um disco estragado.
pub fn ler_bloco(
    bloco_: u64,
    id: &[u8; 16],
    indice: u64,
    destino: &mut [u8; TAM_BLOCO],
) -> Result<(), &'static str> {
    let (g, chave) = para_blocos()?;
    let (inicio, blocos) = area_de_dados(&g)?;
    if bloco_ >= blocos {
        return Err("bloco fora da area de dados");
    }
    let setor = inicio + bloco_ * SETORES_POR_BLOCO;
    crate::virtio::blk::com_o_disco(|d| d.ler(setor, &mut destino[..])).ok_or("nao ha disco")??;
    bloco::abrir(&chave, &g.id, id, indice, destino)?;
    Ok(())
}

/// Um lote escrito no journal do armazém, descarregado, à espera da
/// confirmação no journal de estado.
pub struct Escrito {
    montado: diario::Montado,
    pub confirmado: Confirmado,
}

/// Escreve o registro de um lote no journal dos metadados e descarrega o
/// disco — com ele, os blocos do conteúdo já escritos. Com a ordem das
/// gravações na mão. O lote ainda não vale: ver [`confirmar`].
pub fn escrever_lote(lote: &Lote) -> Result<Escrito, &'static str> {
    exigir()?;
    let (chave, _) = chaves().ok_or("sem a chave do Duke")?;
    let dados = registro::lote(&lote.mudancas)?;
    if dados.len() > diario::MAIOR_CONTEUDO {
        return Err("o lote nao cabe num registro: divida-o");
    }
    compactar_se_preciso(&chave, dados.len())?;
    let (c, regiao, escritor) = com(|v| (v.confirmado, v.regiao, v.escritor.take()));
    let (Some(c), Some(escritor)) = (c, escritor) else {
        return Err("o volume do armazem nao esta aberto");
    };
    let resultado = (|| {
        let montado = escritor.montar(
            &chave,
            nonce()?,
            &diario::Conteudo {
                tipo: tipo::ARMAZEM,
                versao_da_politica: 0,
                tempo: crate::persistencia::agora(),
                dados: &dados,
            },
        )?;
        let mut r = regioes(&c.geometria)?;
        let r = &mut r[regiao];
        r.escrever(montado.setor, &montado.bytes)?;
        r.descarregar()?;
        #[cfg(feature = "quedas")]
        crate::quedas::aqui(crate::quedas::Ponto::LoteNoVolume);
        Ok(montado)
    })();
    com(|v| v.escritor = Some(escritor));
    match resultado {
        Ok(montado) => Ok(Escrito {
            confirmado: Confirmado {
                geometria: c.geometria,
                ancora: montado.ancora,
                elo: montado.elo(),
            },
            montado,
        }),
        Err(m) => {
            // Nada foi confirmado: o escritor não andou, e o próximo
            // registro vai no mesmo lugar. Mas um disco que recusou uma
            // escrita não recebe outra até o boot.
            com(|v| v.estado = Estado::Indisponivel("uma gravacao no volume falhou"));
            Err(m)
        }
    }
}

/// O journal de estado confirmou o lote: o escritor passa para depois
/// dele. Com a ordem das gravações na mão.
pub fn confirmar(escrito: Escrito) {
    com(|v| {
        if let Some(e) = v.escritor.as_mut()
            && e.confirmar(&escrito.montado, escrito.montado.ancora)
                .is_ok()
        {
            v.confirmado = Some(escrito.confirmado);
        } else {
            v.estado = Estado::Indisponivel("o escritor do armazem nao confirmou o lote");
        }
    });
}

/// O journal de estado **não** confirmou o lote — a gravação dele falhou:
/// o volume fica indisponível até o boot, que decide pelo que o journal de
/// estado tem. Os blocos do lote continuam reservados: se o registro de
/// estado chegou ao disco, eles são de arquivos.
pub fn nao_confirmado() {
    com(|v| v.estado = Estado::Indisponivel("a confirmacao de um lote do armazem falhou"));
}

/// Compacta o journal dos metadados se ele passou do ponto, ou se o
/// próximo registro de `tamanho` bytes não cabe: escreve na outra região
/// uma base — os nós em ordem de caminho, a próxima versão, e o fecho com a
/// geometria — e a confirma no journal de estado. A região velha não é
/// tocada: até a confirmação, ela é a que vale.
fn compactar_se_preciso(chave: &[u8; 32], tamanho: usize) -> Result<(), &'static str> {
    let (ocupados, total) = com(|v| v.escritor.as_ref().map(|e| e.ocupacao()))
        .ok_or("o volume do armazem nao esta aberto")?;
    let precisa = (tamanho as u64).div_ceil(diario::TAM_SETOR as u64) + 2;
    if ocupados * 4 < total * COMPACTAR_A_PARTIR_DE_QUARTOS && total - ocupados > precisa {
        return Ok(());
    }
    compactar(chave)
}

/// A compactação do journal dos metadados — ver [`compactar_se_preciso`].
fn compactar(chave: &[u8; 32]) -> Result<(), &'static str> {
    let (c, regiao, escritor) = com(|v| (v.confirmado, v.regiao, v.escritor.take()));
    let (Some(c), Some(escritor)) = (c, escritor) else {
        return Err("o volume do armazem nao esta aberto");
    };
    let outra = 1 - regiao;
    let resultado = (|| {
        let mut regs = regioes(&c.geometria)?;
        let r = &mut regs[outra];
        let mut base = escritor.base(r.setores())?;
        // As entradas, em partes que cabem num registro.
        let mut entradas: Vec<Vec<u8>> = crate::armazem::com_o_armazem(|a| {
            a.todos()
                .map(|(caminho, no)| registro::codificar_no(caminho, no))
                .chain(core::iter::once(registro::proxima(a.proxima())))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let mut parte: Vec<&[u8]> = Vec::new();
        let mut tamanho = 0usize;
        let teto = diario::MAIOR_CONTEUDO - 64;
        let mut partes: Vec<Vec<u8>> = Vec::new();
        for e in &entradas {
            if tamanho + e.len() + 2 > teto && !parte.is_empty() {
                partes.push(diario::estado::campos(&parte)?);
                parte.clear();
                tamanho = 0;
            }
            parte.push(e);
            tamanho += e.len() + 2;
        }
        if !parte.is_empty() {
            partes.push(diario::estado::campos(&parte)?);
        }
        for p in &partes {
            let pronta = base.parte(chave, nonce()?, 0, crate::persistencia::agora(), p)?;
            r.escrever(pronta.setor, &pronta.bytes)?;
        }
        let fecho = diario::estado::campos(&[&registro::volume(&c.geometria)?])?;
        let fechada = base.fechar(chave, nonce()?, 0, crate::persistencia::agora(), &fecho)?;
        r.escrever(fechada.setor, &fechada.bytes)?;
        r.descarregar()?;
        for e in &mut entradas {
            politica::sigiloso::zerar_bloco(e);
        }
        let nova = Confirmado {
            geometria: c.geometria,
            ancora: fechada.ancora,
            elo: fechada.elo(),
        };
        crate::persistencia::confirmar_armazem(&nova, 0)?;
        let ancora = fechada.ancora;
        Ok((fechada.confirmar(ancora)?, nova))
    })();
    match resultado {
        Ok((novo, nova)) => {
            com(|v| {
                v.escritor = Some(novo);
                v.regiao = outra;
                v.confirmado = Some(nova);
            });
            crate::log_info!(
                "armazem",
                "journal dos metadados compactado na regiao {}",
                outra
            );
            Ok(())
        }
        Err(m) => {
            com(|v| {
                v.escritor = Some(escritor);
                v.estado = Estado::Indisponivel("a compactacao do armazem falhou");
            });
            Err(m)
        }
    }
}

/// Só para a suíte: compacta agora o journal dos metadados.
#[cfg(feature = "modo-teste")]
pub fn compactar_de_teste() -> Result<(), &'static str> {
    crate::persistencia::em_ordem(|| {
        exigir()?;
        let (chave, _) = chaves().ok_or("sem a chave do Duke")?;
        compactar(&chave)
    })
}

/// Só para a suíte: o volume reaberto do disco, como no boot, com o que o
/// journal de estado confirma agora — o armazém em memória é trocado pelo
/// que o volume repõe.
#[cfg(feature = "modo-teste")]
pub fn reabrir_de_teste() -> Result<(), &'static str> {
    let c = confirmado();
    crate::persistencia::em_ordem(|| abrir(c));
    exigir()
}

/// Só para a suíte: força o estado do volume, e devolve o anterior.
#[cfg(feature = "modo-teste")]
pub fn forcar_estado_de_teste(novo: Estado) -> Estado {
    com(|v| core::mem::replace(&mut v.estado, novo))
}

/// Só para a suíte: a região que vale e o que ela ocupa.
#[cfg(feature = "modo-teste")]
pub fn regiao_de_teste() -> (usize, u64, u64) {
    com(|v| {
        let (o, t) = v.escritor.as_ref().map_or((0, 0), |e| e.ocupacao());
        (v.regiao, o, t)
    })
}

/// Só para a suíte: os blocos em uso no mapa.
#[cfg(feature = "modo-teste")]
pub fn usados_de_teste() -> u64 {
    com(|v| v.mapa.as_ref().map_or(0, |m| m.contar_usados()))
}

/// Destrava o volume à força, para uso exclusivo do caminho de falha
/// fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        VOLUME.force_unlock();
    }
}
