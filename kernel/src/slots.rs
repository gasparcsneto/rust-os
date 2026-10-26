//! A atualização A/B, do lado do kernel: o slot de onde ele veio, a
//! conferência da imagem, o pacote, a reconciliação do boot, a escrita da
//! versão nova no slot inativo e a instalação por quórum.
//!
//! As regras — os formatos, a tabela da reconciliação, as transições — são
//! do crate `atualizacao`, testadas no hospedeiro, com uma simulação de
//! quedas de energia em cada escrita. Aqui está o que só o kernel faz: ler
//! e escrever o disco, o journal, a auditoria, a autoridade. Ver
//! `docs/ATUALIZACAO.md`.
//!
//! # O caminho de um boot
//!
//! 1. [`registrar`]: o que o iniciador contou na entrega — o slot, o modo,
//!    o resumo do manifesto. Chamado pela arquitetura, antes do heap.
//! 2. [`anotar`]: as partições da tabela, e a janela de escrita do
//!    controle.
//! 3. [`conferir_e_montar`]: com a raiz montada, a imagem de onde o kernel
//!    veio — o cabeçalho do slot, o manifesto, a assinatura com uma chave
//!    do registro da máquina ([`CAMINHO_DAS_CHAVES`]), a arquitetura, o
//!    formato do estado, e o pacote, lido inteiro para a memória, conferido
//!    e montado por cima da raiz.
//! 4. [`reconciliar`]: com a persistência aberta, a decisão do crate,
//!    executada — o journal primeiro, o controle depois, a auditoria de
//!    cada desfecho —; reinicia, se a decisão manda.
//! 5. [`confirmar_se_pendente`]: no fim do boot, a confirmação da versão
//!    nova que bootou numa tentativa.
//!
//! # A autoridade
//!
//! Um boot recusado pela reconciliação — a imagem abaixo do piso, a que
//! nem é a ativa nem a candidata, a que não confere — não decide nada:
//! [`exigir`], que a persistência consulta em toda operação de
//! autoridade, devolve o motivo. Uma versão nova entre a reconciliação e a
//! confirmação também não: ela ainda não é a ativa. O que não muda estado
//! — o `update.status`, os registros, a leitura — continua respondendo,
//! para quem precisa entender o que houve.
//!
//! # Uma máquina sem as partições
//!
//! Um disco de antes da atualização A/B, ou um que não a quer: nada aqui
//! acontece, o kernel veio da ESP, e os comandos da atualização respondem
//! que a máquina não tem slots. Um disco com só parte delas está quebrado,
//! e a autoridade é recusada.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use atualizacao::cabecalho::{self, KERNEL_EM, TAM_CABECALHO};
use atualizacao::controle::{self, Controle, Modo};
use atualizacao::disco::COPIA_EM;
use atualizacao::estado::{self, Arranque, Decisao, Estado, Imagem, Journal, Reinicio};
use atualizacao::manifesto::{self, Manifesto};
use atualizacao::{Arquitetura, Resumidor, Slot, TAM_RESUMO, pacote};
use politica::Codigo;

use crate::bloco::{self, Janela, MAIOR_LEITURA, TAMANHO_DO_SETOR};
use crate::trava::Mutex;

/// O formato do estado persistente — o journal e o armazém — que este
/// kernel lê e grava. Uma imagem nova só se instala se o manifesto dela
/// diz que lê este formato: é a garantia de que o kernel novo lê o journal
/// e o armazém do velho, e de que o velho, numa volta antes da
/// confirmação, ainda lê o que o novo deixou.
pub const FORMATO_DO_ESTADO: u32 = 1;

/// O registro das chaves de atualização da máquina: as públicas Ed25519
/// que podem assinar um manifesto, no formato do registro de editores —
/// `ed25519:<hex> <nome>` por linha. Mora na raiz, com a identidade e a
/// política: é da máquina, e uma atualização não o troca.
pub const CAMINHO_DAS_CHAVES: &str = "/etc/duke/atualizacao";

#[cfg(target_arch = "x86_64")]
const ARQUITETURA: Arquitetura = Arquitetura::X86_64;
#[cfg(target_arch = "aarch64")]
const ARQUITETURA: Arquitetura = Arquitetura::Aarch64;

/// Os setores de uma partição, em setores de [`TAMANHO_DO_SETOR`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lugar {
    primeiro: u64,
    setores: u64,
}

impl Lugar {
    fn bytes(&self) -> u64 {
        self.setores * TAMANHO_DO_SETOR as u64
    }
}

/// A autoridade deste boot, pela reconciliação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Autoridade {
    Livre,
    /// A versão nova bootou, e ainda não se confirmou.
    Pendente,
    Recusada(&'static str),
}

struct Estados {
    /// As partições: o controle e os dois slots. `None` numa máquina sem
    /// a atualização.
    controle: Option<Lugar>,
    slots: [Option<Lugar>; 2],
    /// Só parte das partições: o disco está quebrado.
    incompleto: bool,
    /// A imagem que bootou, conferida — ou o motivo da recusa.
    imagem: Option<Result<Imagem, &'static str>>,
    /// A chave do registro que assinou a imagem que bootou.
    assinada_por: Option<String>,
    /// O estado da atualização, como o journal o deixou.
    estado: Option<Estado>,
    autoridade: Autoridade,
    /// A confirmação esperando o fim do boot: o estado novo e o controle.
    confirmacao: Option<(Estado, Option<Controle>)>,
    /// O estado que uma operação de quórum vai gravar, entre a anotação no
    /// registro e a gravação dele.
    a_gravar: Option<Estado>,
    /// O slot com a janela de escrita.
    janela: Option<Slot>,
    /// O que a reconciliação decidiu, para o `update.status`.
    decisao: &'static str,
}

static ESTADOS: Mutex<Estados> = Mutex::new(Estados {
    controle: None,
    slots: [None, None],
    incompleto: false,
    imagem: None,
    assinada_por: None,
    estado: None,
    autoridade: Autoridade::Livre,
    confirmacao: None,
    a_gravar: None,
    janela: None,
    decisao: "nenhuma",
});

/// O que o iniciador contou, guardado sem trava: chega antes do heap e da
/// conferência da ordem das travas. Zero no slot é nenhum.
static SLOT_DO_ARRANQUE: AtomicU8 = AtomicU8::new(0);
static MODO_DO_ARRANQUE: AtomicU8 = AtomicU8::new(0);
static MANIFESTO_DO_ARRANQUE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// O kernel bootou numa tentativa, e ainda não se confirmou: um pânico
/// reinicia em vez de parar — ver [`em_tentativa`].
static EM_TENTATIVA: AtomicBool = AtomicBool::new(false);

/// O slot inativo está sendo escrito, ou conferido para a instalação: um
/// pedido de cada vez. Uma bandeira, e não uma trava: a conferência lê
/// dezenas de mebibytes, e ninguém gira esperando — quem chega na vez de
/// outro é recusado, e tenta de novo.
static OCUPADO: AtomicBool = AtomicBool::new(false);

fn com<R>(f: impl FnOnce(&mut Estados) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ESTADOS.lock()))
}

/// Destrava à força, para o caminho de falha fatal — ver
/// [`crate::traps::fatal`].
///
/// # Safety
///
/// Só com o kernel em falha irrecuperável, e os outros núcleos parados.
pub unsafe fn destravar() {
    unsafe { ESTADOS.force_unlock() };
}

/// Guarda o que o iniciador contou na entrega.
pub fn registrar(a: protocolo::Arranque) {
    let valido =
        Slot::do_byte(a.slot).is_some() && Modo::do_byte(a.modo).is_some() && a.reservado == [0; 6];
    if !valido {
        return;
    }
    for (i, pedaco) in a.manifesto.as_chunks::<8>().0.iter().enumerate() {
        MANIFESTO_DO_ARRANQUE[i].store(u64::from_le_bytes(*pedaco), Ordering::Relaxed);
    }
    MODO_DO_ARRANQUE.store(a.modo, Ordering::Relaxed);
    SLOT_DO_ARRANQUE.store(a.slot, Ordering::Release);
    if Modo::do_byte(a.modo) == Some(Modo::Tentativa) {
        EM_TENTATIVA.store(true, Ordering::Release);
    }
}

/// O que o iniciador contou, se o kernel veio de um slot.
pub fn arranque() -> Option<Arranque> {
    let slot = Slot::do_byte(SLOT_DO_ARRANQUE.load(Ordering::Acquire))?;
    let modo = Modo::do_byte(MODO_DO_ARRANQUE.load(Ordering::Relaxed))?;
    let mut manifesto = [0u8; TAM_RESUMO];
    for (i, pedaco) in manifesto.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        *pedaco = MANIFESTO_DO_ARRANQUE[i]
            .load(Ordering::Relaxed)
            .to_le_bytes();
    }
    Some(Arranque {
        slot,
        modo,
        manifesto,
    })
}

/// Se este boot é uma tentativa ainda sem confirmação: o pânico e a falha
/// fatal reiniciam a máquina, para o iniciador contar a tentativa e voltar
/// à versão velha quando elas acabarem. Fora de uma tentativa, a máquina
/// para, como sempre: reiniciar uma versão que entra em pânico seria um
/// laço.
pub fn em_tentativa() -> bool {
    EM_TENTATIVA.load(Ordering::Acquire)
}

/// Se a máquina tem a atualização A/B: as três partições.
pub fn tem_slots() -> bool {
    com(|s| s.controle.is_some())
}

/// A autoridade deste boot, para toda operação que a pede — a
/// persistência consulta em [`crate::persistencia::exigir`].
pub fn exigir() -> Result<(), &'static str> {
    match com(|s| s.autoridade) {
        Autoridade::Livre => Ok(()),
        Autoridade::Pendente => Err("a versao nova ainda nao se confirmou"),
        Autoridade::Recusada(m) => Err(m),
    }
}

fn recusar_a_autoridade(motivo: &'static str) {
    com(|s| s.autoridade = Autoridade::Recusada(motivo));
}

/// As partições da tabela, e a janela de escrita do controle.
pub fn anotar(tabela: &crate::particoes::Tabela) {
    use crate::particoes::Tipo;
    let lugar = |t| {
        tabela.primeira(t).map(|p| Lugar {
            primeiro: p.primeiro,
            setores: p.setores,
        })
    };
    let (controle, a, b) = (
        lugar(Tipo::Controle),
        lugar(Tipo::SlotA),
        lugar(Tipo::SlotB),
    );
    match (controle, a, b) {
        (None, None, None) => {
            crate::log_info!("slots", "o disco nao tem as particoes da atualizacao A/B");
        }
        (Some(c), Some(a), Some(b)) => {
            com(|s| {
                s.controle = Some(c);
                s.slots = [Some(a), Some(b)];
            });
            match bloco::fixar_janela_de_escrita(Janela::Controle, c.primeiro, c.setores) {
                Ok(()) => crate::log_info!(
                    "slots",
                    "controle em {}..{}, slots a em {} e b em {}",
                    c.primeiro,
                    c.primeiro + c.setores,
                    a.primeiro,
                    b.primeiro
                ),
                Err(m) => crate::log_error!("slots", "a janela do controle nao foi fixada: {}", m),
            }
        }
        _ => {
            crate::log_error!(
                "slots",
                "o disco tem so parte das particoes da atualizacao: a autoridade fica recusada"
            );
            com(|s| s.incompleto = true);
            recusar_a_autoridade("o disco tem so parte das particoes da atualizacao");
        }
    }
}

/// Lê setores do disco do sistema, em pedidos do tamanho que a camada de
/// bloco aceita. `destino` é múltiplo de setor.
fn ler_do_disco(setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
    for (i, pedaco) in destino.chunks_mut(MAIOR_LEITURA).enumerate() {
        let s = setor + (i * MAIOR_LEITURA / TAMANHO_DO_SETOR) as u64;
        bloco::com_o_disco(|d| d.ler(s, pedaco)).unwrap_or(Err("nao ha disco"))?;
    }
    Ok(())
}

/// O resumo de `tamanho` bytes de um slot, a partir de `deslocamento`
/// (múltiplo de setor), lidos em pedaços.
fn resumo_no_disco(
    lugar: Lugar,
    deslocamento: u64,
    tamanho: u64,
) -> Result<[u8; 32], &'static str> {
    let mut r = Resumidor::novo();
    let mut buffer = vec![0u8; MAIOR_LEITURA];
    let mut feito = 0u64;
    while feito < tamanho {
        let falta = tamanho - feito;
        let pedido = (falta.min(MAIOR_LEITURA as u64) as usize).next_multiple_of(TAMANHO_DO_SETOR);
        let setor = lugar.primeiro + (deslocamento + feito) / TAMANHO_DO_SETOR as u64;
        ler_do_disco(setor, &mut buffer[..pedido])?;
        let util = falta.min(pedido as u64) as usize;
        r.somar(&buffer[..util]);
        feito += util as u64;
    }
    Ok(r.terminar())
}

/// O cabeçalho, o manifesto e a assinatura de um slot, conferidos.
struct Conferida {
    imagem: Imagem,
    /// O nome, no registro, da chave que assinou.
    chave: String,
    kernel: manifesto::Parte,
    pacote: manifesto::Parte,
}

/// A chave do registro da máquina que é `publica`, pelo nome.
fn chave_do_registro(publica: &[u8; 32]) -> Result<String, &'static str> {
    let bytes = crate::vfs::ler_tudo(CAMINHO_DAS_CHAVES)
        .map_err(|_| "a maquina nao tem o registro de chaves de atualizacao")?;
    let texto = core::str::from_utf8(&bytes).map_err(|_| "o registro de chaves nao e texto")?;
    for linha in texto.lines() {
        match sigilo::registro::ler_linha_de_editor(linha) {
            Ok(Some((chave, nome))) if chave == *publica => return Ok(nome.to_string()),
            Ok(_) => {}
            Err(_) => return Err("o registro de chaves de atualizacao tem uma linha invalida"),
        }
    }
    Err("a chave que assinou nao esta no registro de atualizacao da maquina")
}

/// Confere o cabeçalho e o manifesto de um slot: o resumo, se `esperado`;
/// a grafia; a assinatura, com uma chave do registro; a arquitetura; o
/// formato do estado; e que a imagem cabe no slot.
fn conferir_cabecalho(
    slot: Slot,
    lugar: Lugar,
    esperado: Option<&[u8; 32]>,
) -> Result<Conferida, &'static str> {
    let mut bloco_do_cabecalho = vec![0u8; TAM_CABECALHO];
    ler_do_disco(lugar.primeiro, &mut bloco_do_cabecalho)?;
    let c = cabecalho::ler(&bloco_do_cabecalho)?;
    let resumo = manifesto::resumo_do_manifesto(c.manifesto);
    if esperado.is_some_and(|e| *e != resumo) {
        return Err("o manifesto do slot nao e o que se esperava");
    }
    let m = Manifesto::ler(c.manifesto).map_err(|(_, motivo)| motivo)?;
    let chave = chave_do_registro(&c.chave)?;
    if !manifesto::conferir(c.manifesto, &c.assinatura, &c.chave) {
        return Err("a assinatura do manifesto nao confere");
    }
    if m.arquitetura != ARQUITETURA {
        return Err("a imagem e de outra arquitetura");
    }
    if !m.le_o_estado(FORMATO_DO_ESTADO) {
        return Err("a imagem nao le o formato de estado desta maquina");
    }
    if !cabecalho::tamanho_da_imagem(&m).is_some_and(|t| t <= lugar.bytes()) {
        return Err("a imagem do manifesto nao cabe no slot");
    }
    let imagem = Imagem::nova(slot, m.geracao, resumo, m.versao).ok_or("versao invalida")?;
    Ok(Conferida {
        imagem,
        chave,
        kernel: m.kernel,
        pacote: m.pacote,
    })
}

/// O pacote de uma imagem conferida, do disco: o resumo e o índice
/// conferidos. Com `guardar`, os bytes vêm junto — para montar.
fn conferir_o_pacote(
    lugar: Lugar,
    c: &Conferida,
    guardar: bool,
) -> Result<Option<Vec<u8>>, &'static str> {
    let em = cabecalho::pacote_em(c.kernel.tamanho);
    if !guardar {
        if c.pacote.tamanho < pacote::TAM_CABECALHO as u64 {
            return Err("o pacote e menor que o cabecalho dele");
        }
        if resumo_no_disco(lugar, em, c.pacote.tamanho)? != c.pacote.resumo {
            return Err("o pacote do slot nao bate com o manifesto");
        }
        // O índice, lido de novo, para conferir as entradas: a primeira
        // leitura só somava.
        let mut cab = vec![0u8; TAMANHO_DO_SETOR];
        ler_do_disco(lugar.primeiro + em / TAMANHO_DO_SETOR as u64, &mut cab)?;
        let indice = pacote::cabecalho(&cab)?.indice as usize;
        if indice as u64 > c.pacote.tamanho {
            return Err("o indice do pacote passa do fim dele");
        }
        let mut bytes = vec![0u8; indice.next_multiple_of(TAMANHO_DO_SETOR)];
        ler_do_disco(lugar.primeiro + em / TAMANHO_DO_SETOR as u64, &mut bytes)?;
        pacote::conferir(&bytes[..indice], c.pacote.tamanho)?;
        return Ok(None);
    }
    let tamanho = usize::try_from(c.pacote.tamanho).map_err(|_| "pacote grande demais")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(tamanho.next_multiple_of(TAMANHO_DO_SETOR))
        .map_err(|_| "nao ha memoria para o pacote do slot")?;
    bytes.resize(tamanho.next_multiple_of(TAMANHO_DO_SETOR), 0);
    ler_do_disco(lugar.primeiro + em / TAMANHO_DO_SETOR as u64, &mut bytes)?;
    bytes.truncate(tamanho);
    if atualizacao::resumo(&bytes) != c.pacote.resumo {
        return Err("o pacote do slot nao bate com o manifesto");
    }
    let indice = pacote::cabecalho(&bytes)?.indice as usize;
    pacote::conferir(
        bytes
            .get(..indice)
            .ok_or("o indice do pacote passa do fim dele")?,
        c.pacote.tamanho,
    )?;
    Ok(Some(bytes))
}

/// Confere a imagem de onde o kernel veio, e monta o pacote dela. Com a
/// raiz montada: o registro de chaves mora nela.
pub fn conferir_e_montar() {
    let (lugares, incompleto) = com(|s| (s.slots, s.incompleto));
    if incompleto {
        return;
    }
    let Some(a) = arranque() else {
        if lugares[0].is_some() {
            crate::log_warn!("slots", "o kernel nao veio de um slot");
        }
        return;
    };
    let Some(lugar) = lugares[a.slot.indice()] else {
        crate::log_error!("slots", "o iniciador diz um slot que o disco nao tem");
        com(|s| s.imagem = Some(Err("o slot da entrega nao existe neste disco")));
        return;
    };
    let conferida = conferir_cabecalho(a.slot, lugar, Some(&a.manifesto)).and_then(|c| {
        let bytes = conferir_o_pacote(lugar, &c, true)?.unwrap_or_default();
        Ok((c, bytes))
    });
    match conferida {
        Ok((c, bytes)) => {
            crate::log_info!(
                "slots",
                "slot {} ({}): geracao {}, versao {}, assinada por `{}`, pacote de {} bytes",
                a.slot.nome(),
                a.modo.nome(),
                c.imagem.geracao,
                c.imagem.versao(),
                c.chave,
                bytes.len()
            );
            montar_o_pacote(bytes);
            com(|s| {
                s.imagem = Some(Ok(c.imagem));
                s.assinada_por = Some(c.chave);
            });
        }
        Err(motivo) => {
            crate::log_error!(
                "slots",
                "a imagem do slot {} nao confere: {}",
                a.slot.nome(),
                motivo
            );
            com(|s| s.imagem = Some(Err(motivo)));
        }
    }
}

/// Repõe o estado de uma entrada do journal: a última vale.
pub fn restaurar(ativo: &[u8], candidato: &[u8]) -> Result<(), &'static str> {
    let e =
        Estado::dos_campos(ativo, candidato).ok_or("estado de atualizacao invalido no journal")?;
    com(|s| s.estado = Some(e));
    Ok(())
}

/// O estado de agora, para a base de uma compactação.
pub fn estado_do_journal() -> Option<Estado> {
    com(|s| s.estado)
}

/// Os campos de uma entrada do journal para `e`.
pub fn campos(e: &Estado) -> (Vec<u8>, Vec<u8>) {
    let (a, n) = e.ativo.codificar();
    let candidato = e.candidato.map_or(Vec::new(), |c| {
        let (b, m) = c.codificar();
        b[..m].to_vec()
    });
    (a[..n].to_vec(), candidato)
}

/// O controle que vale agora no disco, e a cópia dele.
fn ler_o_controle() -> Option<(usize, Controle)> {
    let lugar = com(|s| s.controle)?;
    let mut copias = [None, None];
    for (i, em) in COPIA_EM.iter().enumerate() {
        let mut setor = [0u8; TAMANHO_DO_SETOR];
        if ler_do_disco(lugar.primeiro + em / TAMANHO_DO_SETOR as u64, &mut setor).is_ok() {
            copias[i] = controle::ler(&setor);
        }
    }
    controle::escolher(copias)
}

/// Grava `novo` na cópia que não vale, e descarrega.
fn gravar_o_controle(novo: &Controle) -> Result<Controle, &'static str> {
    let lugar = com(|s| s.controle).ok_or("a maquina nao tem controle de boot")?;
    let vale = ler_o_controle();
    let (onde, gravado) = controle::proxima(vale.as_ref().map(|(i, c)| (*i, c)), novo);
    let setor = lugar.primeiro + COPIA_EM[onde] / TAMANHO_DO_SETOR as u64;
    let bytes = controle::escrever(&gravado);
    bloco::com_o_disco(|d| {
        d.gravar_setores(Janela::Controle, setor, &bytes)?;
        d.descarregar_disco()
    })
    .unwrap_or(Err("nao ha disco"))?;
    #[cfg(feature = "quedas")]
    crate::quedas::controle_gravado();
    Ok(gravado)
}

/// Grava o controle, se há o que gravar; a falha vai para o log e para a
/// auditoria, e não desfaz nada: o journal já decidiu, e o próximo boot
/// regrava.
fn gravar_se_ha(gravar: Option<Controle>) -> bool {
    let Some(c) = gravar else {
        return false;
    };
    match gravar_o_controle(&c) {
        Ok(g) => {
            crate::log_info!(
                "slots",
                "controle gravado: sequencia {}, bom {}, tentativa {}, restantes {}",
                g.sequencia,
                g.bom.nome(),
                g.tentativa.map_or("nenhuma", Slot::nome),
                g.restantes
            );
            true
        }
        Err(m) => {
            crate::log_error!("slots", "o controle nao gravou: {}", m);
            crate::autorizacao::auditar_do_kernel(
                "system.update.control",
                "",
                Codigo::Error,
                &format!("o controle nao gravou: {m}; o proximo boot regrava pelo journal"),
            );
            false
        }
    }
}

/// O resumo em hexadecimal, inteiro.
pub fn hex(r: &[u8; 32]) -> String {
    String::from_utf8_lossy(&atualizacao::hex_do_resumo(r)).into_owned()
}

/// Uma imagem, curta, para o detalhe da auditoria e o log: o slot, a
/// geração e a versão. O resumo inteiro do manifesto vai no recurso do
/// registro — o detalhe tem teto, e o motivo vem antes.
fn descrever(i: &Imagem) -> String {
    format!("slot {} g{} {}", i.slot.nome(), i.geracao, i.versao())
}

/// Registra `novo` no journal — num registro próprio, que avança a
/// âncora —, com a decisão da auditoria no mesmo registro: o recurso é o
/// manifesto de `imagem`, a de que se trata; o detalhe, o motivo e ela.
fn registrar_no_journal(
    novo: &Estado,
    imagem: &Imagem,
    metodo: &str,
    motivo: &str,
) -> Result<(), &'static str> {
    let detalhe = format!("{}; {}", motivo, descrever(imagem));
    let decisao = crate::autorizacao::auditar_do_kernel(
        metodo,
        &hex(&imagem.manifesto),
        Codigo::Allow,
        &detalhe,
    );
    let (ativo, candidato) = campos(novo);
    crate::persistencia::gravar_atualizacao(&ativo, &candidato, motivo, decisao)?;
    com(|s| s.estado = Some(*novo));
    Ok(())
}

/// Fixa a janela de escrita do slot inativo — uma vez por boot.
fn fixar_a_janela_do_inativo(e: &Estado) {
    let inativo = e.inativo();
    let Some(lugar) = com(|s| s.slots[inativo.indice()]) else {
        return;
    };
    if com(|s| s.janela.is_some()) {
        return;
    }
    match bloco::fixar_janela_de_escrita(Janela::Slot, lugar.primeiro, lugar.setores) {
        Ok(()) => {
            com(|s| s.janela = Some(inativo));
            crate::log_info!(
                "slots",
                "janela de escrita: o slot inativo, {}",
                inativo.nome()
            );
        }
        Err(m) => crate::log_error!("slots", "a janela do slot inativo nao foi fixada: {}", m),
    }
}

/// A reconciliação do boot — ver `atualizacao::estado::reconciliar` —,
/// executada. Com a persistência aberta, antes de qualquer serviço.
pub fn reconciliar() {
    let (temos, incompleto, imagem, estado_lido) =
        com(|s| (s.controle.is_some(), s.incompleto, s.imagem, s.estado));
    if !temos || incompleto {
        return;
    }
    let a = arranque();
    // Na suíte do ARM, o kernel sobe sem o iniciador, pelo `-kernel`, com
    // o disco de testes — que tem os slots. Ela segue sem reconciliar, e
    // os comandos da atualização ficam recusados. Fora da suíte, um kernel
    // de fora de um slot numa máquina A/B não tem autoridade se o journal
    // já tem o estado da atualização — ver `Decisao::SemSlot`.
    #[cfg(feature = "modo-teste")]
    if a.is_none() {
        crate::log_warn!("slots", "suite fora de um slot: sem reconciliacao");
        com(|s| s.decisao = "fora de um slot, na suite");
        return;
    }
    let journal = match (crate::persistencia::estado(), &estado_lido) {
        (crate::persistencia::Estado::Disponivel, None) => Journal::SemEstado,
        (crate::persistencia::Estado::Disponivel, Some(e)) => Journal::Com(e),
        _ => Journal::Indisponivel,
    };
    let imagem = match &imagem {
        Some(Ok(i)) => Ok(i),
        Some(Err(m)) => Err(*m),
        None => Err("a imagem do slot nao foi conferida"),
    };
    let controle = ler_o_controle().map(|(_, c)| c);
    let d = estado::reconciliar(a.as_ref(), imagem, journal, controle.as_ref());
    executar(d, a);
}

/// O nome de uma decisão, para o log e o `update.status`.
fn nome(d: &Decisao) -> &'static str {
    match d {
        Decisao::Seguir { .. } => "seguir",
        Decisao::LinhaDeBase { .. } => "linha de base",
        Decisao::Confirmar { .. } => "confirmar no fim do boot",
        Decisao::Desfazer { .. } => "desfazer",
        Decisao::Recusar { .. } => "recusar",
        Decisao::SemPersistencia => "sem persistencia",
        Decisao::SemSlot => "fora de um slot, sem estado de atualizacao",
    }
}

fn executar(d: Decisao, a: Option<Arranque>) {
    let modo = a.map_or("fora de slot", |a| a.modo.nome());
    crate::log_info!("slots", "reconciliacao ({}): {}", modo, nome(&d));
    com(|s| s.decisao = nome(&d));
    match d {
        Decisao::Seguir { gravar } => {
            if gravar.is_some() {
                crate::autorizacao::auditar_do_kernel(
                    "system.update.control",
                    &a.map_or(String::new(), |a| hex(&a.manifesto)),
                    Codigo::Allow,
                    &format!("o controle volta a dizer o journal; modo {modo}"),
                );
            }
            gravar_se_ha(gravar);
            if let Some(e) = com(|s| s.estado) {
                fixar_a_janela_do_inativo(&e);
            }
        }
        Decisao::LinhaDeBase { estado, gravar } => {
            match registrar_no_journal(
                &estado,
                &estado.ativo,
                "system.update.baseline",
                "linha de base",
            ) {
                Ok(()) => {
                    gravar_se_ha(gravar);
                    fixar_a_janela_do_inativo(&estado);
                }
                Err(m) => {
                    crate::log_error!("slots", "a linha de base nao gravou: {}", m);
                    recusar_a_autoridade("a linha de base da atualizacao nao ficou gravada");
                }
            }
        }
        Decisao::Confirmar { estado, gravar } => {
            crate::autorizacao::auditar_do_kernel(
                "system.update.attempt",
                &hex(&estado.ativo.manifesto),
                Codigo::Allow,
                &format!(
                    "tentativa conferida, a confirmar no fim do boot; {}",
                    descrever(&estado.ativo)
                ),
            );
            com(|s| {
                s.confirmacao = Some((estado, gravar));
                s.autoridade = Autoridade::Pendente;
            });
        }
        Decisao::Desfazer {
            estado,
            gravar,
            motivo,
        } => {
            let desfeita = com(|s| s.estado.and_then(|e| e.candidato));
            let imagem = desfeita.unwrap_or(estado.ativo);
            match registrar_no_journal(&estado, &imagem, "system.update.rollback", motivo) {
                Ok(()) => {
                    crate::log_warn!("slots", "a versao nova foi desfeita: {}", motivo);
                    gravar_se_ha(gravar);
                    fixar_a_janela_do_inativo(&estado);
                }
                Err(m) => {
                    crate::log_error!("slots", "o desfazimento nao gravou: {}", m);
                    recusar_a_autoridade("o desfazimento da versao nova nao ficou gravado");
                }
            }
        }
        Decisao::Recusar {
            motivo,
            gravar,
            reinicio,
        } => {
            let seq = crate::autorizacao::auditar_do_kernel(
                "system.update.refuse",
                &a.map_or(String::new(), |a| hex(&a.manifesto)),
                Codigo::DenyPolicy,
                &format!(
                    "{}; {}, modo {modo}",
                    motivo,
                    a.map_or("fora de slot", |a| a.slot.nome())
                ),
            );
            crate::log_error!("slots", "este boot nao tem autoridade: {}", motivo);
            recusar_a_autoridade(motivo);
            let gravou = gravar_se_ha(gravar);
            let reiniciar = match reinicio {
                Reinicio::Sim => true,
                Reinicio::SeGravou => gravou,
                Reinicio::Nao => false,
            };
            if reiniciar {
                reiniciar_agora(seq);
            }
        }
        Decisao::SemPersistencia | Decisao::SemSlot => {}
    }
}

/// Reinicia já, pela energia: a auditoria até `seq` no journal, as
/// gravações paradas, e o firmware — ver
/// [`crate::energia::reiniciar_pela_atualizacao`].
fn reiniciar_agora(seq: u64) {
    crate::log_warn!("slots", "reiniciando para o slot que o controle diz");
    #[cfg(feature = "modo-teste")]
    REINICIO_PEDIDO.store(true, Ordering::Release);
    crate::energia::reiniciar_pela_atualizacao(seq);
}

/// Só na suíte: o reinício que a reconciliação pediria — e o esquece.
#[cfg(feature = "modo-teste")]
static REINICIO_PEDIDO: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "modo-teste")]
pub fn reinicio_pedido_de_teste() -> bool {
    REINICIO_PEDIDO.swap(false, Ordering::AcqRel)
}

/// Só na suíte: a recusa de um boot pelo caminho de verdade — o registro
/// dela, a autoridade recusada e o reinício pedido —, sem controle a
/// gravar. Devolve com que a autoridade de antes volta.
#[cfg(feature = "modo-teste")]
pub fn recusar_de_teste(motivo: &'static str) -> impl FnOnce() {
    let (autoridade, decisao) = com(|s| (s.autoridade, s.decisao));
    executar(
        Decisao::Recusar {
            motivo,
            gravar: None,
            reinicio: Reinicio::Sim,
        },
        arranque(),
    );
    move || {
        com(|s| {
            s.autoridade = autoridade;
            s.decisao = decisao;
        })
    }
}

/// A confirmação da versão nova, no fim do boot: depois dos núcleos e
/// antes de os programas e os canais subirem. É o ponto sem volta — o
/// piso sobe para a geração dela, e a velha não boota mais.
pub fn confirmar_se_pendente() {
    let Some((estado, gravar)) = com(|s| s.confirmacao.take()) else {
        return;
    };
    #[cfg(feature = "quedas")]
    crate::quedas::antes_da_confirmacao();
    let motivo = "confirmada: bootou numa tentativa e conferiu";
    match registrar_no_journal(&estado, &estado.ativo, "system.update.confirm", motivo) {
        Ok(()) => {
            EM_TENTATIVA.store(false, Ordering::Release);
            com(|s| s.autoridade = Autoridade::Livre);
            crate::log_info!(
                "slots",
                "a versao nova e a ativa: {}; o piso sobe para {}",
                descrever(&estado.ativo),
                estado.piso()
            );
            gravar_se_ha(gravar);
            fixar_a_janela_do_inativo(&estado);
        }
        Err(m) => {
            // Sem a confirmação no journal, esta versão não é a ativa: a
            // tentativa continua contando, e o boot seguinte tenta de novo
            // ou volta para a velha.
            crate::log_error!("slots", "a confirmacao nao gravou: {}", m);
            recusar_a_autoridade("a confirmacao da versao nova nao ficou gravada");
            let seq = crate::autorizacao::auditar_do_kernel(
                "system.update.refuse",
                &hex(&estado.ativo.manifesto),
                Codigo::Error,
                &format!("a confirmacao nao gravou: {m}"),
            );
            reiniciar_agora(seq);
        }
    }
}

// --- O pacote ---------------------------------------------------------------

/// Um nó do pacote: um arquivo, com o lugar dele nos bytes, ou um
/// diretório, com os filhos.
struct NoDoPacote {
    nome: String,
    diretorio: bool,
    deslocamento: u64,
    tamanho: u64,
    filhos: Vec<usize>,
}

/// O pacote montado: os bytes inteiros, e a árvore. O nó 0 é o topo, que
/// não se monta: cada diretório dele vai para `/<nome>`.
struct Pacote {
    bytes: Vec<u8>,
    nos: Vec<NoDoPacote>,
}

impl Pacote {
    fn de(bytes: Vec<u8>) -> Result<Pacote, &'static str> {
        let indice = pacote::cabecalho(&bytes)?.indice as usize;
        let mut nos = vec![NoDoPacote {
            nome: String::new(),
            diretorio: true,
            deslocamento: 0,
            tamanho: 0,
            filhos: Vec::new(),
        }];
        for e in pacote::entradas(&bytes[..indice], bytes.len() as u64) {
            let e = e?;
            let mut atual = 0usize;
            let partes: Vec<&str> = e.caminho.split('/').collect();
            for (i, parte) in partes.iter().enumerate() {
                let ultimo = i + 1 == partes.len();
                let achado = nos[atual]
                    .filhos
                    .iter()
                    .copied()
                    .find(|&f| nos[f].nome == *parte);
                atual = match achado {
                    Some(f) if nos[f].diretorio && !ultimo => f,
                    Some(_) => return Err("o pacote tem um caminho repetido"),
                    None => {
                        nos.push(NoDoPacote {
                            nome: parte.to_string(),
                            diretorio: !ultimo,
                            deslocamento: if ultimo { e.deslocamento } else { 0 },
                            tamanho: if ultimo { e.tamanho } else { 0 },
                            filhos: Vec::new(),
                        });
                        let novo = nos.len() - 1;
                        nos[atual].filhos.push(novo);
                        novo
                    }
                };
            }
        }
        Ok(Pacote { bytes, nos })
    }
}

/// Um diretório do topo do pacote, montado em `/<nome>`.
struct Visao {
    pacote: Arc<Pacote>,
    raiz: usize,
}

impl Visao {
    fn no(&self, i: usize) -> crate::vfs::No {
        let n = &self.pacote.nos[i];
        crate::vfs::No {
            tipo: if n.diretorio {
                crate::vfs::Tipo::Diretorio
            } else {
                crate::vfs::Tipo::Arquivo
            },
            id: i as u64,
            tamanho: n.tamanho,
        }
    }
}

impl crate::vfs::SistemaDeArquivos for Visao {
    fn raiz(&self) -> crate::vfs::No {
        self.no(self.raiz)
    }

    fn procurar(
        &self,
        dir: &crate::vfs::No,
        nome: &str,
    ) -> Result<crate::vfs::No, crate::vfs::Erro> {
        let d = self
            .pacote
            .nos
            .get(dir.id as usize)
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;
        d.filhos
            .iter()
            .copied()
            .find(|&f| self.pacote.nos[f].nome == nome)
            .map(|f| self.no(f))
            .ok_or(crate::vfs::Erro::NaoEncontrado)
    }

    fn ler(
        &self,
        no: &crate::vfs::No,
        deslocamento: u64,
        destino: &mut [u8],
    ) -> Result<usize, crate::vfs::Erro> {
        let n = self
            .pacote
            .nos
            .get(no.id as usize)
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;
        if n.diretorio {
            return Err(crate::vfs::Erro::NaoEhArquivo);
        }
        if deslocamento >= n.tamanho {
            return Ok(0);
        }
        let quanto = destino.len().min((n.tamanho - deslocamento) as usize);
        let inicio = (n.deslocamento + deslocamento) as usize;
        destino[..quanto].copy_from_slice(&self.pacote.bytes[inicio..inicio + quanto]);
        Ok(quanto)
    }

    fn listar(
        &self,
        dir: &crate::vfs::No,
        indice: usize,
    ) -> Result<Option<crate::vfs::Entrada>, crate::vfs::Erro> {
        let d = self
            .pacote
            .nos
            .get(dir.id as usize)
            .ok_or(crate::vfs::Erro::NaoEncontrado)?;
        Ok(d.filhos.get(indice).map(|&f| {
            let n = &self.pacote.nos[f];
            crate::vfs::Entrada {
                nome: n.nome.clone(),
                tipo: if n.diretorio {
                    crate::vfs::Tipo::Diretorio
                } else {
                    crate::vfs::Tipo::Arquivo
                },
            }
        }))
    }
}

/// Monta cada diretório do topo do pacote em `/<nome>`, por cima da raiz:
/// a montagem mais longa responde, e o que o pacote traz cobre o que a
/// raiz tivesse no mesmo caminho. Da imagem: o pacote veio assinado com o
/// kernel, e o código dele roda sem selo, como o da raiz.
fn montar_o_pacote(bytes: Vec<u8>) {
    if bytes.len() <= pacote::TAM_CABECALHO {
        return;
    }
    let pacote = match Pacote::de(bytes) {
        Ok(p) => Arc::new(p),
        Err(m) => {
            crate::log_error!("slots", "o pacote nao se monta: {}", m);
            return;
        }
    };
    let topo: Vec<usize> = pacote.nos[0].filhos.clone();
    for raiz in topo {
        let em = format!("/{}", pacote.nos[raiz].nome);
        let visao = Visao {
            pacote: pacote.clone(),
            raiz,
        };
        match crate::vfs::montar("pacote", &em, crate::vfs::Origem::Imagem, Box::new(visao)) {
            Ok(()) => crate::log_info!("vfs", "{} montado do pacote do slot", em),
            Err(e) => crate::log_error!("vfs", "{} nao montou: {}", em, e.motivo()),
        }
    }
}

// --- A versão nova: a escrita e a instalação --------------------------------

/// Por que um pedido da atualização não foi feito: o código e o motivo.
pub type Falha = (Codigo, String);

fn falha(codigo: Codigo, motivo: impl Into<String>) -> Falha {
    (codigo, motivo.into())
}

/// O que todo pedido que muda a atualização exige: a máquina com slots, a
/// autoridade deste boot, o journal com estado, e nenhum reinício a
/// caminho.
fn exigir_para_mudar() -> Result<Estado, Falha> {
    if !tem_slots() {
        return Err(falha(
            Codigo::Error,
            "a maquina nao tem os slots da atualizacao",
        ));
    }
    if arranque().is_none() {
        return Err(falha(Codigo::Error, "o kernel nao veio de um slot"));
    }
    crate::persistencia::exigir().map_err(|m| falha(Codigo::Error, m))?;
    if crate::energia::pedida().is_some() {
        return Err(falha(
            Codigo::Conflict,
            "a maquina esta reiniciando ou desligando",
        ));
    }
    com(|s| s.estado)
        .ok_or_else(|| falha(Codigo::Error, "o journal nao tem o estado da atualizacao"))
}

/// A vez no slot inativo: devolvida ao sair do escopo.
struct Vez;

impl Vez {
    fn tomar() -> Result<Vez, Falha> {
        OCUPADO
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Vez)
            .map_err(|_| {
                falha(
                    Codigo::Conflict,
                    "o slot inativo esta ocupado por outro pedido: tente de novo",
                )
            })
    }
}

impl Drop for Vez {
    fn drop(&mut self) {
        OCUPADO.store(false, Ordering::Release);
    }
}

/// `update.stage`: escreve `dados` no slot inativo, a partir de
/// `deslocamento` — um múltiplo de setor; o último pedaço pode ser curto, e
/// é completado com zeros até o setor. Nada no journal: o que se escreve
/// aqui não é nada até uma operação de quórum o armar — e a instalação
/// confere o slot inteiro de novo.
///
/// Recusado com uma versão nova armada: o slot dela não se escreve por
/// cima.
pub fn encenar(deslocamento: u64, dados: &[u8]) -> Result<(Slot, u64), Falha> {
    if dados.is_empty() {
        return Err(falha(Codigo::InvalidArgument, "nada a escrever"));
    }
    if !deslocamento.is_multiple_of(TAMANHO_DO_SETOR as u64) {
        return Err(falha(
            Codigo::InvalidArgument,
            "o deslocamento nao e multiplo de setor",
        ));
    }
    // A vez antes do estado: uma instalação que armasse a versão entre a
    // leitura do estado e a escrita teria o slot dela escrito por cima. Com
    // a vez na mão, nenhuma instalação anda até a escrita acabar — e a que
    // acabou antes já está no estado lido aqui.
    let _vez = Vez::tomar()?;
    let e = exigir_para_mudar()?;
    if let Some(c) = e.candidato {
        return Err(falha(
            Codigo::Conflict,
            format!(
                "ha uma versao nova armada no slot {}: cancele-a antes de escrever",
                c.slot.nome()
            ),
        ));
    }
    let inativo = e.inativo();
    let (lugar, janela) = com(|s| (s.slots[inativo.indice()], s.janela));
    let lugar = lugar.ok_or_else(|| falha(Codigo::Error, "o slot inativo nao existe"))?;
    if janela != Some(inativo) {
        return Err(falha(
            Codigo::Error,
            "o slot inativo nao tem janela de escrita neste boot",
        ));
    }
    let fim = deslocamento.checked_add(dados.len() as u64);
    if fim.is_none_or(|f| f > lugar.bytes()) {
        return Err(falha(Codigo::InvalidArgument, "passa do fim do slot"));
    }
    // O controle diz o journal antes de o slot mudar: o inativo, sem
    // manifesto, não boota no meio da escrita.
    let atual = ler_o_controle().map(|(_, c)| c);
    let alvo = e.controle(atual.as_ref());
    if atual.is_none_or(|a| !a.mesmo_que(&alvo)) {
        gravar_o_controle(&alvo)
            .map_err(|m| falha(Codigo::Error, format!("o controle nao gravou: {m}")))?;
    }
    let mut setores = dados.to_vec();
    setores.resize(dados.len().next_multiple_of(TAMANHO_DO_SETOR), 0);
    let primeiro = lugar.primeiro + deslocamento / TAMANHO_DO_SETOR as u64;
    for (i, pedaco) in setores.chunks(MAIOR_LEITURA).enumerate() {
        let setor = primeiro + (i * MAIOR_LEITURA / TAMANHO_DO_SETOR) as u64;
        bloco::com_o_disco(|d| d.gravar_setores(Janela::Slot, setor, pedaco))
            .unwrap_or(Err("nao ha disco"))
            .map_err(|m| falha(Codigo::Error, m))?;
    }
    bloco::com_o_disco(|d| d.descarregar_disco())
        .unwrap_or(Err("nao ha disco"))
        .map_err(|m| falha(Codigo::Error, m))?;
    #[cfg(feature = "quedas")]
    crate::quedas::encenacao_gravada();
    Ok((inativo, deslocamento + dados.len() as u64))
}

/// A instalação conferida, antes do registro: a imagem e a vez no slot,
/// presa até a operação acabar.
pub struct Preparada {
    imagem: Imagem,
    chave: String,
    _vez: Vez,
}

impl Preparada {
    /// O que a auditoria leva da instalação, além do manifesto, que é o
    /// recurso: a imagem, quem a assinou, e de que slot para qual.
    pub fn detalhe(&self, de: Slot) -> String {
        format!(
            "instalar {}, de `{}`, ativa no {}",
            descrever(&self.imagem),
            self.chave,
            de.nome()
        )
    }

    pub fn imagem(&self) -> &Imagem {
        &self.imagem
    }
}

/// Confere o slot inativo inteiro para a instalação de `manifesto`: o
/// cabeçalho, a assinatura, o kernel, o pacote, e a geração acima do piso.
/// Fora da ordem das gravações — lê dezenas de mebibytes —, com a vez no
/// slot presa: nenhuma escrita o muda até a operação acabar.
pub fn preparar_a_instalacao(manifesto: &str) -> Result<Preparada, Falha> {
    let esperado = atualizacao::resumo_do_hex(manifesto).ok_or_else(|| {
        falha(
            Codigo::InvalidArgument,
            "manifest precisa ser o resumo em 64 digitos hexadecimais minusculos",
        )
    })?;
    // A vez antes do estado, como em [`encenar`]: o slot inativo e a
    // candidata lidos daqui em diante são os de quem tem a vez.
    let vez = Vez::tomar()?;
    let e = exigir_para_mudar()?;
    let inativo = e.inativo();
    let lugar = com(|s| s.slots[inativo.indice()])
        .ok_or_else(|| falha(Codigo::Error, "o slot inativo nao existe"))?;
    let c = conferir_cabecalho(inativo, lugar, Some(&esperado))
        .map_err(|m| falha(Codigo::DenyPolicy, m))?;
    if resumo_no_disco(lugar, KERNEL_EM, c.kernel.tamanho).map_err(|m| falha(Codigo::Error, m))?
        != c.kernel.resumo
    {
        return Err(falha(
            Codigo::DenyPolicy,
            "o kernel do slot nao bate com o manifesto",
        ));
    }
    conferir_o_pacote(lugar, &c, false).map_err(|m| falha(Codigo::DenyPolicy, m))?;
    e.armar(c.imagem)
        .map_err(|m| falha(Codigo::DenyPolicy, m))?;
    Ok(Preparada {
        imagem: c.imagem,
        chave: c.chave,
        _vez: vez,
    })
}

/// Arma a versão nova, com a ordem das gravações na mão: o estado novo vai
/// para o registro da operação de quórum, pela anotação da persistência —
/// e só vira o de agora depois de gravado, em [`depois_da_gravacao`].
pub fn armar(p: &Preparada) -> Result<Estado, Falha> {
    let e = com(|s| s.estado)
        .ok_or_else(|| falha(Codigo::Error, "o journal nao tem o estado da atualizacao"))?;
    let novo = e
        .armar(p.imagem)
        .map_err(|m| falha(Codigo::DenyPolicy, m))?;
    anotar_no_registro(&novo, "armada por quorum")?;
    Ok(novo)
}

/// Desiste da versão nova armada — que tem de ser `manifesto` —, com a
/// ordem das gravações na mão, como [`armar`].
pub fn cancelar(manifesto: &str) -> Result<(Estado, Imagem), Falha> {
    let e = exigir_para_mudar()?;
    let c = e
        .candidato
        .ok_or_else(|| falha(Codigo::Conflict, "nao ha versao nova armada"))?;
    if atualizacao::resumo_do_hex(manifesto) != Some(c.manifesto) {
        return Err(falha(
            Codigo::Conflict,
            "a versao nova armada e outra: o manifest nao confere",
        ));
    }
    let novo = e.cancelar().map_err(|m| falha(Codigo::Conflict, m))?;
    anotar_no_registro(&novo, "cancelada por quorum")?;
    Ok((novo, c))
}

fn anotar_no_registro(novo: &Estado, motivo: &str) -> Result<(), Falha> {
    let (ativo, candidato) = campos(novo);
    let entrada = crate::persistencia::entrada_da_atualizacao(&ativo, &candidato, motivo)
        .map_err(|m| falha(Codigo::Error, m))?;
    crate::persistencia::anotar(Ok(entrada));
    com(|s| s.a_gravar = Some(*novo));
    Ok(())
}

/// Depois da gravação do registro da operação: com ela, o estado novo é o
/// de agora, e o controle passa a dizê-lo. `Ok(true)` se o controle
/// gravou; `Ok(false)` se não — o journal já decidiu, e o boot seguinte
/// completa.
pub fn depois_da_gravacao(gravado: bool) -> bool {
    let Some(novo) = com(|s| s.a_gravar.take()) else {
        return false;
    };
    if !gravado {
        return false;
    }
    com(|s| s.estado = Some(novo));
    let atual = ler_o_controle().map(|(_, c)| c);
    match gravar_o_controle(&novo.controle(atual.as_ref())) {
        Ok(_) => true,
        Err(m) => {
            crate::log_error!(
                "slots",
                "o journal registrou e o controle nao gravou: {}; o proximo boot completa",
                m
            );
            false
        }
    }
}

// --- O `update.status` ------------------------------------------------------

/// O que o `update.status` diz: o boot, o journal, o controle e o slot
/// inativo.
pub fn relatar(w: &mut crate::agent::json::JsonWriter) -> core::fmt::Result {
    let (temos, incompleto, imagem, assinada, estado, autoridade, janela, decisao) = com(|s| {
        (
            s.controle.is_some(),
            s.incompleto,
            s.imagem,
            s.assinada_por.clone(),
            s.estado,
            s.autoridade,
            s.janela,
            s.decisao,
        )
    });
    w.field_bool("slots", temos)?;
    w.field_bool("partial", incompleto)?;
    w.field_u64("state_format", u64::from(FORMATO_DO_ESTADO))?;
    w.field_str("reconciliation", decisao)?;
    w.field_str(
        "authority",
        match autoridade {
            Autoridade::Livre => "granted",
            Autoridade::Pendente => "pending_confirmation",
            Autoridade::Recusada(_) => "refused",
        },
    )?;
    if let Autoridade::Recusada(m) = autoridade {
        w.field_str("refused_because", m)?;
    }
    w.key("booted")?;
    match arranque() {
        Some(a) => {
            w.begin_object()?;
            w.field_str("slot", a.slot.nome())?;
            w.field_str("mode", a.modo.nome())?;
            w.field_str("manifest", &hex(&a.manifesto))?;
            match imagem {
                Some(Ok(i)) => {
                    w.field_bool("verified", true)?;
                    w.field_u64("generation", i.geracao)?;
                    w.field_str("version", i.versao())?;
                    if let Some(k) = &assinada {
                        w.field_str("signed_by", k)?;
                    }
                }
                Some(Err(m)) => {
                    w.field_bool("verified", false)?;
                    w.field_str("error", m)?;
                }
                None => w.field_bool("verified", false)?,
            }
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    w.key("journal")?;
    match estado {
        Some(e) => {
            w.begin_object()?;
            w.field_u64("floor", e.piso())?;
            w.key("active")?;
            imagem_em_json(w, &e.ativo)?;
            w.key("candidate")?;
            match e.candidato {
                Some(c) => imagem_em_json(w, &c)?,
                None => w.null_value()?,
            }
            w.field_str("inactive_slot", e.inativo().nome())?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    w.key("control")?;
    match ler_o_controle() {
        Some((i, c)) => {
            w.begin_object()?;
            w.field_u64("copy", i as u64)?;
            w.field_u64("sequence", c.sequencia)?;
            w.field_str("good", c.bom.nome())?;
            match c.tentativa {
                Some(t) => w.field_str("trial", t.nome())?,
                None => {
                    w.key("trial")?;
                    w.null_value()?
                }
            }
            w.field_u64("remaining", u64::from(c.restantes))?;
            // A falha que o iniciador ou a versão nova marcaram — nenhuma é
            // `null`: as tentativas que se esgotam sem falha se leem nas
            // restantes.
            match c.falha {
                atualizacao::controle::Falha::Nenhuma => {
                    w.key("failure")?;
                    w.null_value()?
                }
                f => w.field_str("failure", f.motivo())?,
            }
            w.field_bool("synthesized", c.sintetizado)?;
            for s in [Slot::A, Slot::B] {
                let chave = if s == Slot::A {
                    "manifest_a"
                } else {
                    "manifest_b"
                };
                match c.manifesto(s) {
                    Some(m) => w.field_str(chave, &hex(&m))?,
                    None => {
                        w.key(chave)?;
                        w.null_value()?
                    }
                }
            }
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    w.field_bool(
        "inactive_writable",
        janela.is_some() && estado.is_some_and(|e| Some(e.inativo()) == janela),
    )?;
    Ok(())
}

fn imagem_em_json(w: &mut crate::agent::json::JsonWriter, i: &Imagem) -> core::fmt::Result {
    w.begin_object()?;
    w.field_str("slot", i.slot.nome())?;
    w.field_u64("generation", i.geracao)?;
    w.field_str("version", i.versao())?;
    w.field_str("manifest", &hex(&i.manifesto))?;
    w.end_object()
}
