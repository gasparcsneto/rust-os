//! A persistência: o journal na partição de estado, ancorado no TPM.
//!
//! # O que este módulo garante
//!
//! Que uma mudança no estado de autoridade — um agente registrado ou
//! revogado, um papel atribuído, a política escrita, uma pessoa registrada,
//! revogada ou com a credencial trocada, uma sessão encerrada, uma
//! credencial administrativa revogada por quórum — sobrevive a um boot, e
//! que um disco devolvido a uma cópia anterior não faz o sistema voltar a
//! antes dela. Em particular: uma credencial administrativa revogada não
//! reaparece válida depois de uma reinicialização. Ver
//! `docs/PERSISTENCIA.md`, requisitos R1 a R6.
//!
//! # As peças
//!
//! - O formato e as regras do journal são do pacote `diario`, testado no
//!   hospedeiro.
//! - O contador monotônico do TPM é do pacote `ancora`; o transporte até o
//!   chip é [`crate::tpm`].
//! - A escrita no disco é [`crate::virtio::blk`], restrita à janela da
//!   partição de estado — e este é o **único** módulo que a chama: a
//!   conferência de invariantes do `xtask` recusa qualquer outro.
//!
//! # Gravar antes de responder
//!
//! Uma operação que muda autoridade passa por aqui duas vezes: antes, para
//! saber se há persistência confiável (sem ela a operação é recusada, sem
//! exceção para o `sistema`); depois, para gravar o que ela mudou. A
//! gravação é: montar o registro, escrevê-lo, descarregar o disco, avançar
//! o contador do TPM. Só então a operação responde. Se a gravação falhar,
//! a mudança que concedia algo é desfeita; a que tirava algo fica — nunca
//! se fica mais fraco do que o pedido — e a persistência passa a
//! indisponível, o que bloqueia as próximas.
//!
//! # A auditoria
//!
//! Todo registro gravado leva, no fim, os registros da cadeia da auditoria
//! que ainda não estão no disco, na ordem da cadeia — ver
//! [`politica::auditoria`]. A decisão que autorizou uma operação de
//! autoridade é registrada **antes** da gravação, e a gravação exige que
//! ela vá junto ([`concluir`]): a operação e a auditoria dela entram no
//! journal no mesmo registro, ou nenhuma das duas. O que não muda estado —
//! uma leitura, uma recusa — vai no próximo registro de qualquer tipo, ou
//! num registro só de auditoria que o coletor grava de tempos em tempos
//! ([`gravar_auditoria_se_preciso`]).
//!
//! # O boot
//!
//! [`abrir`] roda depois de o registro da imagem, a política e as pessoas
//! carregarem, e **antes** de as portas abrirem e de o primeiro desafio
//! administrativo existir. Ela lê o journal, julga contra o contador do
//! TPM, e reaplica cada registro autêntico — mesmo quando o julgamento
//! recusa o journal: o que ele diz é mais recente que a imagem, e uma
//! lápide lida é uma credencial a menos. Recusado, o journal deixa a
//! administração bloqueada até alguém resolver por fora.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use politica::auditoria::Cadeia;

use crate::trava::Mutex;
use diario::estado::{self, tipo};
use diario::{Conteudo, Escritor, Meio, Relogio, Veredito};

/// O índice de NV do contador da âncora, na faixa que a especificação do
/// TCG reserva para o dono do TPM.
pub const INDICE_DA_ANCORA: u32 = 0x0180_D0E0;

/// O índice do nascimento da âncora: o valor que o contador tinha quando
/// nasceu — ver o módulo `ancora`. É o que separa uma criação interrompida
/// de um disco apagado.
pub const INDICE_DO_NASCIMENTO: u32 = 0x0180_D0E1;

/// O que a persistência é agora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Ainda não aberta: o boot não chegou lá.
    Fechada,
    /// O journal é o atual, e uma gravação é possível.
    Disponivel,
    /// Não há como gravar com confiança: sem disco durável, sem TPM, sem a
    /// chave do Duke, ou uma gravação que falhou. As operações de
    /// autoridade ficam bloqueadas.
    Indisponivel(&'static str),
    /// O journal não confere com a âncora: o disco é anterior ao que o TPM
    /// já viu, ou o TPM não é o deste disco. As operações de autoridade
    /// ficam bloqueadas, e o que o journal disse foi reaplicado.
    Recusada(&'static str),
}

impl Estado {
    pub fn como_str(&self) -> &'static str {
        match self {
            Estado::Fechada => "closed",
            Estado::Disponivel => "available",
            Estado::Indisponivel(_) => "unavailable",
            Estado::Recusada(_) => "refused",
        }
    }

    pub fn motivo(&self) -> &'static str {
        match self {
            Estado::Fechada => "a persistencia ainda nao foi aberta",
            Estado::Disponivel => "",
            Estado::Indisponivel(m) | Estado::Recusada(m) => m,
        }
    }
}

/// O que a persistência guarda entre uma gravação e outra.
struct Aberta {
    escritor: Escritor,
    ancora: ancora::Ancora,
    chave: [u8; 32],
}

struct Persistencia {
    estado: Estado,
    aberta: Option<Aberta>,
    /// A geração administrativa: sobe a cada mudança de autoridade.
    geracao: u64,
    /// Quantos registros o journal tem.
    registros: u64,
    /// Quantos deles são só de auditoria.
    registros_de_auditoria: u64,
    /// Quantos boots o journal contou, este incluído.
    boots: u64,
    relogio: Relogio,
    /// O identificador da instalação, do registro de abertura.
    instalacao: Option<[u8; 16]>,
    /// A região em que o journal mora: 0 ou 1.
    regiao: usize,
    /// Quantas compactações o journal já teve.
    compactacoes: u64,
}

static PERSISTENCIA: Mutex<Persistencia> = Mutex::new(Persistencia {
    estado: Estado::Fechada,
    aberta: None,
    geracao: 0,
    registros: 0,
    registros_de_auditoria: 0,
    boots: 0,
    relogio: Relogio::novo(0),
    instalacao: None,
    regiao: 0,
    compactacoes: 0,
});

/// A última sequência da auditoria que está no journal.
static AUDITORIA_GRAVADA: AtomicU64 = AtomicU64::new(0);

/// O elo do último registro da auditoria que está no journal: de onde a
/// cadeia continua na base de uma compactação, mesmo que o anel da memória
/// já não o tenha.
static ELO_GRAVADO: Mutex<[u8; 32]> = Mutex::new([0; 32]);

/// A auditoria está no journal até `ate`, cujo elo é `elo`.
fn auditoria_foi_gravada(ate: u64, elo: [u8; 32]) {
    crate::arch::sem_interrupcoes(|| {
        *ELO_GRAVADO.lock() = elo;
        AUDITORIA_GRAVADA.store(ate, Ordering::Release);
    });
}

/// A cadeia que o journal refaz no boot, enquanto ele é lido. Ela só vira
/// a auditoria com o journal confirmado pela âncora — ver [`abrir`].
static REPOSTA: Mutex<Option<Cadeia>> = Mutex::new(None);

/// Quem tem a ordem das gravações: o fio, como `id + 1`, ou zero.
///
/// Uma gravação de cada vez — o registro seguinte depende do anterior, e o
/// contador do TPM também —, e mais que isso: quem muda o estado que vai
/// ao journal e grava o registro do que mudou faz as duas coisas com a
/// ordem na mão, para que o journal tenha os registros na ordem em que as
/// mudanças aconteceram na memória. O coletor de vencimentos é um fio
/// preemptivo, e sem a ordem a vencida que ele tira poderia entrar no
/// journal antes da confirmação que a precedeu.
///
/// A tranca de [`PERSISTENCIA`] é mantida só enquanto se lê e se troca o
/// estado; esta é a que serializa uma gravação inteira, com o disco e o
/// TPM no meio. Ver [`em_ordem`].
static DONO_DA_ORDEM: AtomicU64 = AtomicU64::new(0);

/// Só na suíte: a próxima gravação falha antes de tocar o disco, como se o
/// disco ou o TPM tivessem recusado.
#[cfg(feature = "modo-teste")]
static FALHAR_A_PROXIMA: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Roda `f` com a ordem das gravações na mão.
///
/// Reentrante pelo mesmo fio — uma operação de autoridade grava o registro
/// dela, e o que ela chama pode querer gravar —, e quem espera cede a CPU
/// em vez de girar: quem tem a ordem pode estar preemptado, e só volta se
/// alguém lhe der o processador. Nunca com as interrupções desligadas.
#[track_caller]
pub fn em_ordem<R>(f: impl FnOnce() -> R) -> R {
    let eu = crate::fios::id_atual() + 1;
    if DONO_DA_ORDEM.load(Ordering::Acquire) == eu {
        return f();
    }
    // A ordem é uma trava também, do fio: pedida com outra na mão, é a
    // aresta que a conferência da ordem precisa ver.
    #[cfg(feature = "modo-teste")]
    crate::ordem_das_travas::ao_pedir_a_ordem();
    while DONO_DA_ORDEM
        .compare_exchange(0, eu, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // Esperar mascarado é esperar com alguma trava na mão — a de quem
        // mascarou —, e quem tem a ordem pode precisar dela: um núcleo
        // parado, sem nenhum erro. Na compilação de depuração, o erro.
        debug_assert!(
            crate::arch::interrupcoes_habilitadas(),
            "a ordem das gravacoes esperada com as interrupcoes mascaradas"
        );
        crate::fios::ceder();
    }
    let r = f();
    DONO_DA_ORDEM.store(0, Ordering::Release);
    r
}

/// Se o fio deste núcleo tem a ordem das gravações, sem tomar trava
/// nenhuma: a conferência da ordem das travas pergunta de dentro de cada
/// `lock`.
#[cfg(feature = "modo-teste")]
pub fn ordem_na_mao_sem_trava() -> bool {
    let eu = crate::fios::id_atual_sem_trava() + 1;
    DONO_DA_ORDEM.load(Ordering::Acquire) == eu
}

fn com<R>(f: impl FnOnce(&mut Persistencia) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut PERSISTENCIA.lock()))
}

/// O estado da persistência.
pub fn estado() -> Estado {
    com(|p| p.estado)
}

/// A geração administrativa em vigor.
pub fn geracao() -> u64 {
    com(|p| p.geracao)
}

/// O relatório para o `system.info`: estado, motivo, geração, âncora,
/// registros e boots.
pub fn relatorio() -> (Estado, u64, Option<u64>, u64, u64) {
    com(|p| {
        (
            p.estado,
            p.geracao,
            p.aberta.as_ref().map(|a| a.escritor.ancora()),
            p.registros,
            p.boots,
        )
    })
}

/// A região do journal, quantas compactações ele já teve, e quantos
/// setores da região estão ocupados, de quantos.
pub fn regiao() -> (usize, u64, u64, u64) {
    com(|p| {
        let (usados, total) = p.aberta.as_ref().map_or((0, 0), |a| a.escritor.ocupacao());
        (p.regiao, p.compactacoes, usados, total)
    })
}

/// Quantos registros do journal são só de auditoria.
pub fn registros_de_auditoria() -> u64 {
    com(|p| p.registros_de_auditoria)
}

/// A última sequência da auditoria que está no journal: escrita,
/// descarregada e ancorada. As posteriores, por enquanto, só em memória.
pub fn auditoria_gravada() -> u64 {
    AUDITORIA_GRAVADA.load(Ordering::Acquire)
}

/// O tempo lógico: o RTC com o piso do journal — nunca volta.
pub fn agora() -> u64 {
    let rtc = crate::relogio::agora();
    com(|p| p.relogio.agora(rtc))
}

/// O tempo lógico em milissegundos, para os prazos das mensagens.
///
/// A resolução é a do RTC: um segundo. Um prazo vence no primeiro segundo
/// lógico que o alcança — nunca antes, e nunca depois de um reboot que
/// volte o RTC, porque o piso não volta. O tempo desde o boot, que teria
/// milissegundos, não serve: recomeça a cada boot, e um prazo medido nele
/// voltaria a correr depois de um.
pub fn agora_ms() -> u64 {
    agora().saturating_mul(1000)
}

// ---------------------------------------------------------------------------
// As mensagens
// ---------------------------------------------------------------------------

/// O que as mensagens mudaram e ainda não está no journal, já como
/// entradas de registro, na ordem em que mudou.
///
/// Quem muda uma mensagem anota aqui, com a ordem das gravações na mão; o
/// próximo registro gravado — o da própria operação de mensagem, ou o de
/// uma operação de autoridade que anulou mensagens — leva tudo. Assim a
/// ordem do journal é a ordem da memória, e uma operação continua sendo um
/// registro só.
static PENDENTES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

fn tirar_pendentes() -> Vec<Vec<u8>> {
    crate::arch::sem_interrupcoes(|| core::mem::take(&mut *PENDENTES.lock()))
}

/// Anota uma entrada para o próximo registro.
///
/// Sem persistência, nada se anota: o que muda vale só em memória, e diz
/// isso — ver [`gravar_mensagens`]. Uma entrada que não se montou não se
/// anota: os campos são todos de tamanho limitado, e não acontece.
pub fn anotar(e: Result<Vec<u8>, &'static str>) {
    let Ok(mut e) = e else {
        return;
    };
    if estado() != Estado::Disponivel {
        politica::sigiloso::zerar_bloco(&mut e);
        return;
    }
    crate::arch::sem_interrupcoes(|| PENDENTES.lock().push(e));
}

/// A entrada de uma mensagem aceita. Pura: não trava nada, e pode ser
/// montada com a tabela de mensagens na mão.
pub fn entrada_criada(g: politica::mensagens::Gravada) -> Result<Vec<u8>, &'static str> {
    entrada(
        tipo::MENSAGEM_CRIADA,
        &[
            &g.id.to_le_bytes(),
            &g.de.bytes(),
            &g.para.bytes(),
            &g.criada_ms.to_le_bytes(),
            &g.expira_ms.to_le_bytes(),
            g.corpo,
        ],
    )
}

/// Transições de mensagens, para o próximo registro.
pub fn anotar_transicoes(ts: &[politica::mensagens::Transicao]) {
    for t in ts {
        anotar(entrada(
            tipo::MENSAGEM_ESTADO,
            &[
                &t.id.to_le_bytes(),
                &[t.estado.codigo()],
                &t.versao.to_le_bytes(),
            ],
        ));
    }
}

/// Grava o que as mensagens mudaram desde o último registro, se mudaram.
/// `Ok` é o que está no disco — escrito, descarregado e ancorado — ou não
/// havia nada a gravar; `Err` é o motivo de a mudança valer só em memória.
///
/// Sem a persistência disponível, as mensagens continuam, só em memória, e
/// quem chama diz isso na resposta. Uma gravação que falha deixa a
/// persistência indisponível, como qualquer outra.
pub fn gravar_mensagens() -> Result<(), &'static str> {
    em_ordem(|| {
        let pendentes = tirar_pendentes();
        let estado = estado();
        if estado != Estado::Disponivel {
            return Err(estado.motivo());
        }
        if pendentes.is_empty() {
            return Ok(());
        }
        let mut conteudo =
            estado::campos(&pendentes.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
        let gravado = gravar(tipo::MENSAGENS, &conteudo);
        // Os corpos não ficam no heap depois de cifrados no disco.
        politica::sigiloso::zerar_bloco(&mut conteudo);
        for mut p in pendentes {
            politica::sigiloso::zerar_bloco(&mut p);
        }
        gravado
    })
}

/// A entrada de uma mudança do armazém — ver [`tipo::ARQUIVO_GRAVADO`] e
/// [`tipo::ARQUIVO_APAGADO`].
fn entrada_do_armazem(m: &::armazem::Mudanca) -> Result<Vec<u8>, &'static str> {
    match m {
        ::armazem::Mudanca::Gravado {
            caminho,
            versao,
            dados,
        } => entrada(
            tipo::ARQUIVO_GRAVADO,
            &[caminho.as_bytes(), &versao.to_le_bytes(), dados],
        ),
        ::armazem::Mudanca::Apagado { caminho, versao } => entrada(
            tipo::ARQUIVO_APAGADO,
            &[caminho.as_bytes(), &versao.to_le_bytes()],
        ),
    }
}

/// Grava uma mudança do armazém, num registro [`tipo::ARMAZEM`] que leva
/// também o registro `execucao` da auditoria — o que o comando fez, depois
/// da decisão do gate que o autorizou — e, como todo registro, o que as
/// mensagens mudaram e ainda não foi gravado.
///
/// **Estrita**: sem a persistência disponível, `Err` antes de gravar
/// qualquer coisa — o armazém não muda só em memória, nunca. `Ok` é o que
/// está no disco: escrito, descarregado e ancorado. Quem chama aplica a
/// mudança em memória **só** depois de `Ok`, com a ordem das gravações
/// ainda na mão. Uma gravação que falha deixa a persistência indisponível,
/// como qualquer outra.
pub fn gravar_armazem(m: &::armazem::Mudanca, execucao: u64) -> Result<(), &'static str> {
    em_ordem(|| {
        exigir()?;
        if execucao == 0 {
            return Err("uma mudanca do armazem sem o registro da auditoria");
        }
        let mut entradas = alloc::vec![entrada_do_armazem(m)?];
        entradas.extend(tirar_pendentes());
        let montado = estado::campos(&entradas.iter().map(Vec::as_slice).collect::<Vec<_>>());
        // O conteúdo de um arquivo não fica no heap depois de cifrado.
        for e in &mut entradas {
            politica::sigiloso::zerar_bloco(e);
        }
        let mut conteudo = montado?;
        let gravado = gravar_com_a_decisao(tipo::ARMAZEM, &conteudo, execucao);
        politica::sigiloso::zerar_bloco(&mut conteudo);
        gravado
    })
}

/// A partição de estado como meio do journal: setores relativos ao começo
/// dela, em pedidos que cabem numa ida ao disco.
struct Particao {
    primeiro: u64,
    setores: u64,
}

impl Meio for Particao {
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
            crate::virtio::blk::com_o_disco(|d| d.gravar_setores(s, &origem[feito..feito + n]))
                .ok_or("nao ha disco")??;
            feito += n;
        }
        Ok(())
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        crate::virtio::blk::com_o_disco(|d| d.descarregar_disco()).ok_or("nao ha disco")?
    }
}

/// A partição de estado: a janela de escrita que o boot fixou. Para ler
/// basta ela; para gravar, ver [`particao`].
fn janela() -> Result<Particao, &'static str> {
    let (primeiro, setores) =
        crate::virtio::blk::com_o_disco(|d| d.janela().unwrap_or((0, 0))).ok_or("nao ha disco")?;
    if setores == 0 {
        return Err("nao ha particao de estado");
    }
    Ok(Particao { primeiro, setores })
}

/// Se uma escrita no disco pode ser tornada durável.
fn duravel() -> Result<(), &'static str> {
    if crate::virtio::blk::com_o_disco(|d| d.duravel()).unwrap_or(false) {
        Ok(())
    } else {
        Err("o disco nao aceita descarga: nenhuma escrita seria duravel")
    }
}

/// O tamanho das regiões, se alguém o encolheu: a suíte, para encher uma
/// região depressa; a bancada, pelo plano dela. Zero é o tamanho inteiro.
#[cfg(feature = "modo-teste")]
static LIMITE_DE_TESTE: AtomicU64 = AtomicU64::new(0);

fn limite() -> Option<u64> {
    #[cfg(feature = "modo-teste")]
    {
        let l = LIMITE_DE_TESTE.load(Ordering::Acquire);
        if l != 0 {
            return Some(l);
        }
    }
    #[cfg(feature = "quedas")]
    if let Some(l) = crate::quedas::limite() {
        return Some(l);
    }
    None
}

/// As duas regiões da partição de estado, como meios do journal — ver
/// `diario::regioes`.
fn regioes() -> Result<[Particao; 2], &'static str> {
    let p = janela()?;
    Ok(
        diario::regioes(p.setores, limite()).map(|(inicio, setores)| Particao {
            primeiro: p.primeiro + inicio,
            setores,
        }),
    )
}

/// A região `i`, para gravar: num disco durável.
fn particao(i: usize) -> Result<Particao, &'static str> {
    duravel()?;
    let [a, b] = regioes()?;
    Ok(if i == 0 { a } else { b })
}

/// Um journal percorrido e vazio: o de uma região que não vale.
fn vazio() -> diario::Percorrido {
    diario::Percorrido::vazio()
}

/// Os campos do fecho de uma base: a instalação, os boots e as
/// compactações.
/// O fecho de uma base: a instalação, os boots, as compactações, e a EK.
struct Fecho {
    instalacao: [u8; 16],
    boots: u64,
    compactacoes: u64,
    ponto: Option<[u8; 64]>,
}

fn fecho(conteudo: &[u8]) -> Result<Fecho, &'static str> {
    let campos = estado::ler_campos(conteudo)?;
    let (instalacao, boots, compactacoes, ponto) = match campos.as_slice() {
        [i, b, c] => (i, b, c, None),
        [i, b, c, p] => (i, b, c, Some(ponto_da_chave(p)?)),
        _ => return Err("o fecho da base nao tem os campos dele"),
    };
    Ok(Fecho {
        instalacao: (*instalacao)
            .try_into()
            .map_err(|_| "instalacao que nao tem 16 bytes")?,
        boots: u64_de(boots)?,
        compactacoes: u64_de(compactacoes)?,
        ponto,
    })
}

fn ponto_da_chave(b: &[u8]) -> Result<[u8; 64], &'static str> {
    b.try_into()
        .map_err(|_| "ponto da chave do TPM que nao tem 64 bytes")
}

/// O ponto da EK que o journal conhece, juntado enquanto ele é lido no
/// boot: o da abertura, de um registro de boot, ou do fecho de uma base.
static FIXADA: Mutex<Option<[u8; 64]>> = Mutex::new(None);

/// O journal diz que a EK é `ponto`. Todo registro que diz isso tem de
/// dizer a mesma: um journal que fala de duas EKs não se confirma.
fn fixar(ponto: [u8; 64]) -> Result<(), &'static str> {
    crate::arch::sem_interrupcoes(|| {
        let mut f = FIXADA.lock();
        match *f {
            Some(antes) if antes != ponto => Err("o journal fala de duas chaves de TPM"),
            _ => {
                *f = Some(ponto);
                Ok(())
            }
        }
    })
}

/// A entrada que fixa a EK, para a abertura e o registro de boot.
fn entrada_da_chave(ponto: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    estado::campos(&[&entrada(tipo::CHAVE_DO_TPM, &[ponto])?])
}

/// O ponto da EK com que o journal fala, se a persistência está aberta.
pub fn ponto_da_ek() -> Option<[u8; 64]> {
    com(|p| p.aberta.as_ref().map(|a| a.ancora.ponto_do_tpm()))
}

/// O ponto da EK com que a persistência fala agora.
fn ponto_atual() -> Result<[u8; 64], &'static str> {
    com(|p| p.aberta.as_ref().map(|a| a.ancora.ponto_do_tpm()))
        .ok_or("a persistencia nao esta aberta")
}

/// A chave do journal e a senha da âncora, derivadas da chave do Duke.
///
/// Duas derivações com rótulos diferentes: a chave que cifra o journal não
/// é a senha que vai pelo barramento até o TPM, e saber uma não dá a outra.
fn segredos() -> Option<([u8; 32], [u8; 32])> {
    crate::identidade::com_chave_do_duke(|k| {
        let sal = b"Duke persistencia v1";
        (
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"journal: cifra"]),
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"ancora: senha do contador"]),
        )
    })
}

/// A âncora recém-conectada no boot. Se o boot não chega a ficar com ela —
/// uma recusa, um erro —, ela sai do TPM com a EK e a sessão: nenhuma
/// saída deixa vaga ocupada no TPM.
struct Conectada(Option<ancora::Ancora>);

impl Drop for Conectada {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            crate::tpm::com_o_tpm(|t| a.encerrar(t));
        }
    }
}

/// O gerador do kernel, para os nonces e o par efêmero da sessão com o
/// TPM.
pub(crate) struct Sorteio;

impl ancora::Sorteio for Sorteio {
    fn sortear(&mut self, destino: &mut [u8]) -> Result<(), ancora::Erro> {
        crate::aleatorio::preencher(destino).map_err(|_| ancora::Erro::SemEntropia)
    }
}

/// Um nonce sorteado para um registro.
fn nonce() -> Result<[u8; diario::TAM_NONCE], &'static str> {
    let mut n = [0u8; diario::TAM_NONCE];
    crate::aleatorio::preencher(&mut n).map_err(|_| "sem entropia para o nonce")?;
    Ok(n)
}

/// Abre a persistência, no boot. Ver o cabeçalho do módulo.
///
/// Inteira com a ordem das gravações na mão. O coletor já roda no boot, e
/// grava a auditoria e compacta assim que a persistência fica disponível:
/// sem a ordem, ele gravaria um registro só de auditoria antes da abertura
/// — e uma região que não começa pela abertura não é um journal inteiro —,
/// ou compactaria antes de as mensagens do journal serem adotadas, numa
/// base sem elas.
pub fn abrir() {
    em_ordem(abrir_em_ordem);
}

fn abrir_em_ordem() {
    let estado = match abrir_de_fato() {
        Ok(e) => e,
        Err(motivo) => Estado::Indisponivel(motivo),
    };
    com(|p| p.estado = estado);
    // A auditoria do journal, se não foi adotada, fica de fora pela mesma
    // razão das mensagens, logo abaixo: a cadeia continua só em memória,
    // do começo — ver [`abrir_de_fato`].
    let _ = crate::arch::sem_interrupcoes(|| REPOSTA.lock().take());
    // As mensagens do journal valem só com ele confirmado pela âncora. Um
    // journal recusado é um disco antigo, ou estragado: as mensagens dele
    // trariam de volta como pendente o que já foi confirmado ou anulado.
    // Sem a âncora, o mesmo, por não se saber. Nesses casos a tabela começa
    // vazia, numa época sorteada, e vale só em memória.
    match (estado, com(|p| p.instalacao)) {
        (Estado::Disponivel, Some(instalacao)) => {
            let mut epoca = [0u8; 8];
            epoca.copy_from_slice(&instalacao[..8]);
            crate::mensagens::adotar(epoca);
        }
        _ => crate::mensagens::descartar(),
    }
    // A reaplicação das revogações anula mensagens, e anota; o journal já
    // tem essas anulações.
    let _ = tirar_pendentes();
    // O desfecho vai para a auditoria — um journal recusado, e por quê,
    // fica registrado como qualquer decisão. Disponível, o registro vai ao
    // journal na próxima gravação: o coletor não espera para isso.
    match estado {
        Estado::Disponivel => {
            let (_, g, a, r, b) = relatorio();
            crate::log_info!(
                "persistencia",
                "journal aberto: {} registros, geracao {}, ancora {}, boot {}",
                r,
                g,
                a.unwrap_or(0),
                b
            );
            crate::autorizacao::auditar_do_kernel(
                "persistence.open",
                "",
                politica::Codigo::Allow,
                &alloc::format!(
                    "available; registros {r}; geracao {g}; ancora {}; boot {b}",
                    a.unwrap_or(0)
                ),
            );
        }
        outro => {
            crate::log_error!(
                "persistencia",
                "{}: {} — as operacoes que mudam autoridade ficam bloqueadas",
                outro.como_str(),
                outro.motivo()
            );
            crate::autorizacao::auditar_do_kernel(
                "persistence.open",
                "",
                politica::Codigo::Error,
                &alloc::format!("{}; {}", outro.como_str(), outro.motivo()),
            );
        }
    }
}

fn abrir_de_fato() -> Result<Estado, &'static str> {
    let (chave, senha) = segredos().ok_or("sem a chave do Duke")?;
    #[cfg(feature = "quedas")]
    crate::quedas::carregar(&mut janela()?);

    // As duas regiões, lidas sem reaplicar nada: qual é o journal é a que
    // está inteira com a última âncora maior — ver `diario::escolher`. A
    // outra é uma compactação que não terminou, ou o journal de antes da
    // última compactação: nenhuma das duas diz nada.
    let mut regioes = regioes()?;
    let mut percorridas = [None, None];
    for (i, r) in regioes.iter_mut().enumerate() {
        percorridas[i] = Some(
            diario::percorrer(r, &chave, |_| Ok::<(), ()>(())).map_err(|e| match e {
                diario::Interrompido::Meio(m) => m,
                diario::Interrompido::Recusado { .. } => "o percurso nao recusa nada aqui",
            })?,
        );
    }
    let percorridas = percorridas.map(|p| p.unwrap_or_else(vazio));
    let escolhida = diario::escolher(&percorridas);
    // Nenhuma inteira, com registros autênticos no disco — só uma base sem
    // fecho, ou duas inteiras com a mesma âncora —, não é um journal novo
    // nem uma criação interrompida: nenhuma das duas chega aí sem que
    // alguém mexa no disco. Recusado, sem escolher.
    if escolhida.is_none() && percorridas.iter().any(|p| p.quantos > 0) {
        return Ok(Estado::Recusada("nenhuma regiao do journal esta inteira"));
    }
    let regiao = escolhida.unwrap_or(0);
    crate::log_info!(
        "persistencia",
        "regioes: {} e {} registros; vale a {}",
        percorridas[0].quantos,
        percorridas[1].quantos,
        match escolhida {
            Some(0) => "primeira",
            Some(_) => "segunda",
            None => "nenhuma",
        }
    );

    // O journal é lido e reaplicado antes de qualquer outra conferência, e
    // vale mesmo que a persistência acabe indisponível ou recusada: o que
    // ele diz é mais recente que a imagem, e uma lápide lida é uma
    // credencial a menos. Ler não precisa de descarga nem de TPM.
    //
    // Um registro de cada vez: o journal pode ocupar a região inteira, e
    // o heap do kernel é bem menor que ela. Do caminho fica só o que o
    // boot precisa — a instalação, o último boot, quantos de auditoria.
    crate::arch::sem_interrupcoes(|| {
        *REPOSTA.lock() = Some(Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA));
    });
    let mut instalacao = None;
    let mut boots = 0u64;
    let mut compactacoes = 0u64;
    let mut de_auditoria = 0u64;
    crate::arch::sem_interrupcoes(|| *FIXADA.lock() = None);
    let lido = match escolhida {
        None => Ok(vazio()),
        Some(i) => diario::percorrer(&mut regioes[i], &chave, |r| {
            reaplicar(&r)?;
            match r.tipo {
                tipo::ABERTURA if r.sequencia == 0 => {
                    instalacao =
                        primeiro_campo(&r.conteudo).and_then(|id| <[u8; 16]>::try_from(id).ok());
                }
                tipo::BOOT => {
                    boots = primeiro_campo(&r.conteudo)
                        .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                        .unwrap_or(0);
                }
                tipo::BASE_FIM => {
                    let f = fecho(&r.conteudo)?;
                    instalacao = Some(f.instalacao);
                    boots = f.boots;
                    compactacoes = f.compactacoes;
                    if let Some(p) = f.ponto {
                        fixar(p)?;
                    }
                }
                tipo::AUDITORIA => de_auditoria += 1,
                _ => {}
            }
            Ok::<(), &'static str>(())
        }),
    };
    let lido = match lido {
        Ok(l) => l,
        Err(diario::Interrompido::Meio(m)) => return Err(m),
        Err(diario::Interrompido::Recusado { sequencia, motivo }) => {
            crate::log_error!(
                "persistencia",
                "o registro {} nao se reaplica: {}",
                sequencia,
                motivo
            );
            return Ok(Estado::Recusada(
                "um registro autentico do journal nao se reaplica",
            ));
        }
    };
    // As anulações que a reposição das revogações anotou já estão no
    // journal: nada fica pendente — e a compactação do boot, logo abaixo,
    // exige isso.
    for mut e in tirar_pendentes() {
        politica::sigiloso::zerar_bloco(&mut e);
    }
    if let diario::Parada::Ilegivel { setor, motivo } = lido.parada {
        crate::log_warn!(
            "persistencia",
            "a leitura parou no setor {} da regiao: {}",
            setor,
            motivo
        );
    }
    if let Some(id) = instalacao {
        com(|p| p.instalacao = Some(id));
    }
    if let Some(ultimo) = lido.ultimo {
        crate::autorizacao::fixar_versao_da_politica(ultimo.versao_da_politica);
        com(|p| {
            p.geracao = ultimo.geracao;
            p.relogio = Relogio::novo(ultimo.tempo);
        });
    }
    com(|p| {
        p.registros = lido.quantos;
        p.registros_de_auditoria = de_auditoria;
        p.boots = boots;
        p.compactacoes = compactacoes;
        p.regiao = regiao;
    });

    let fixada = crate::arch::sem_interrupcoes(|| FIXADA.lock().take());
    // Na suíte: o journal fixou outra EK — como diante de outro TPM.
    #[cfg(feature = "modo-teste")]
    let fixada = match fixada {
        Some(mut f) if EK_TROCADA.swap(false, Ordering::AcqRel) => {
            f[0] ^= 1;
            Some(f)
        }
        f => f,
    };

    // Agora, se dá para gravar: um disco durável e a âncora.
    duravel()?;
    // Um journal que existe foi ancorado num TPM. Sem o TPM, ele não se
    // confirma — e um disco devolvido a uma cópia antiga, com o TPM tirado
    // da máquina, traria de volta um agente revogado. Recusado, como
    // qualquer journal que a âncora não confirma. Sem journal e sem TPM é
    // uma máquina sem TPM: a persistência fica só indisponível.
    if !crate::tpm::presente() {
        if lido.quantos > 0 {
            return Ok(Estado::Recusada(
                "ha journal e nenhum TPM: nada confirma que o disco e o atual",
            ));
        }
        return Err("sem TPM: nao ha ancora contra um disco restaurado");
    }
    // Daqui em diante, toda falha do TPM — a EK que não é a fixada, uma
    // resposta que não confere com a sessão, um transporte que não
    // responde — é um journal que não se confirma: recusado.
    let recusa = |e: ancora::Erro| Ok(Estado::Recusada(e.motivo()));

    // Uma âncora de uma abertura anterior — na suíte, que reabre — sai do
    // TPM antes: a EK e a sessão dela ocupam vagas, e um TPM tem poucas.
    if let Some(velha) = com(|p| p.aberta.take()) {
        crate::tpm::com_o_tpm(|t| velha.ancora.encerrar(t));
    }
    // A autenticação: a EK do TPM, conferida com a fixada no journal. A
    // sessão salgada com ela abre no primeiro comando ao contador.
    let conectada = crate::tpm::com_o_tpm(|t| {
        ancora::Ancora::conectar(t, INDICE_DA_ANCORA, senha, fixada.as_ref())
    })
    .ok_or("sem TPM")?;
    let mut guarda = Conectada(Some(match conectada {
        Ok(a) => a,
        Err(e) => return recusa(e),
    }));
    let a = guarda.0.as_mut().expect("posta acima");
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDaChave);
    // O contador: lido pela sessão, ou ausente.
    let lido_do_tpm = crate::tpm::com_o_tpm(|t| -> Result<Option<u64>, ancora::Erro> {
        if a.existe(t)? {
            #[cfg(feature = "quedas")]
            if crate::quedas::contador_de_fora() {
                a.incrementar(t, &mut Sorteio)?;
            }
            a.valor(t, &mut Sorteio).map(Some)
        } else {
            Ok(None)
        }
    })
    .ok_or("sem TPM")?;
    let valor = match lido_do_tpm {
        Ok(v) => v,
        Err(e) => return recusa(e),
    };

    let total = regioes[regiao].setores();
    // A decisão.
    let valor = match (lido.quantos == 0, valor) {
        // Um journal vazio diante de uma âncora presente. Se o contador
        // nunca passou do valor com que nasceu, nenhum registro foi
        // confirmado contra ele: a criação foi interrompida — entre criar a
        // âncora e gravar a abertura —, e retomá-la não perde nada. Se
        // passou, houve registros, e o disco que os tinha foi apagado.
        (true, Some(v)) => {
            let nascimento =
                crate::tpm::com_o_tpm(|t| a.nascimento(t, INDICE_DO_NASCIMENTO, &mut Sorteio))
                    .ok_or("sem TPM")?;
            match nascimento {
                Ok(Some(n)) if n == v => {}
                // Sem nascimento guardado, a criação parou antes de
                // guardá-lo — e ele só é guardado antes do primeiro
                // registro, então nenhum registro existiu.
                Ok(None) => {
                    if let Err(e) = crate::tpm::com_o_tpm(|t| {
                        a.registrar_nascimento(t, INDICE_DO_NASCIMENTO, &[], &mut Sorteio)
                    })
                    .ok_or("sem TPM")?
                    {
                        return recusa(e);
                    }
                }
                Ok(Some(_)) => {
                    return Ok(Estado::Recusada(
                        diario::Recusa::JournalApagado { ancora: v }.motivo(),
                    ));
                }
                Err(e) => return recusa(e),
            }
            crate::log_warn!(
                "persistencia",
                "a criacao da ancora foi interrompida antes da abertura: retomada em {}",
                v
            );
            v
        }
        (_, valor) => match diario::julgar(lido.ultima_ancora(), valor) {
            Veredito::Recusado(r) => return Ok(Estado::Recusada(r.motivo())),
            Veredito::Confere => valor.ok_or("ancora sumiu")?,
            Veredito::Completar => {
                let novo =
                    match crate::tpm::com_o_tpm(|t| a.avancar(t, &mut Sorteio)).ok_or("sem TPM")? {
                        Ok(v) => v,
                        Err(e) => return recusa(e),
                    };
                if Some(novo) != lido.ultima_ancora() {
                    return Ok(Estado::Recusada(
                        "a ancora nao chegou ao ultimo registro ao completar o avanco",
                    ));
                }
                crate::log_warn!(
                    "persistencia",
                    "o ultimo registro estava gravado e a ancora nao: avanco completado"
                );
                novo
            }
            Veredito::Novo => {
                // Criar, e guardar o nascimento antes de qualquer registro.
                // O primeiro avanço é o da abertura — o mesmo caminho que
                // retoma um contador definido e nunca avançado.
                let criado = crate::tpm::com_o_tpm(|t| {
                    a.definir(t, &[], &mut Sorteio)?;
                    #[cfg(feature = "quedas")]
                    crate::quedas::aqui(crate::quedas::Ponto::AncoraDefinida);
                    a.valor(t, &mut Sorteio)?;
                    #[cfg(feature = "quedas")]
                    crate::quedas::aqui(crate::quedas::Ponto::AncoraAvancada);
                    let v = a.registrar_nascimento(t, INDICE_DO_NASCIMENTO, &[], &mut Sorteio)?;
                    #[cfg(feature = "quedas")]
                    crate::quedas::aqui(crate::quedas::Ponto::NascimentoGuardado);
                    Ok::<_, ancora::Erro>(v)
                })
                .ok_or("sem TPM")?;
                let v = match criado {
                    Ok(v) => v,
                    Err(e) => return recusa(e),
                };
                crate::log_info!("persistencia", "ancora criada no TPM, em {}", v);
                v
            }
        },
    };
    let ancora = guarda.0.take().expect("posta acima");
    let escritor = Escritor::depois_de(&lido, valor, total);
    let novo = escritor.ancora() == valor && lido.quantos == 0;
    // O journal está confirmado pela âncora: a cadeia que ele refez vira a
    // auditoria, e o que este boot registrou até aqui continua depois
    // dela — e vai no registro de boot, logo abaixo.
    if let Some(reposta) = crate::arch::sem_interrupcoes(|| REPOSTA.lock().take()) {
        auditoria_foi_gravada(reposta.ultima_seq(), reposta.cabeca());
        crate::autorizacao::adotar_auditoria(reposta);
    }
    com(|p| {
        p.aberta = Some(Aberta {
            escritor,
            ancora,
            chave,
        });
        p.estado = Estado::Disponivel;
    });
    if novo {
        // Na bancada: duas voltas do coletor entre a persistência
        // disponível e a abertura. Ele não grava nada antes dela, porque a
        // ordem das gravações está com o boot — ver [`abrir`].
        #[cfg(feature = "quedas")]
        if crate::quedas::esperar_na_abertura() {
            let ate = crate::tempo::uptime_ms() + 2 * INTERVALO_DA_AUDITORIA_MS;
            while crate::tempo::uptime_ms() < ate {
                crate::fios::ceder();
            }
        }
        let mut instalacao = [0u8; 16];
        crate::aleatorio::preencher(&mut instalacao).map_err(|_| "sem entropia")?;
        let mut dados = estado::campos(&[&instalacao])?;
        dados.extend_from_slice(&entrada_da_chave(&ponto_atual()?)?);
        gravar(tipo::ABERTURA, &dados)?;
        com(|p| p.instalacao = Some(instalacao));
    }
    // O boot é um ponto seguro: o que está em memória é o que o journal
    // disse, e nada mais mudou. Uma região que passou do ponto — ou que
    // encheu e deixou o boot anterior sem gravar — compacta aqui, antes do
    // registro de boot. Se a base não couber, o boot tenta gravar assim
    // mesmo, e uma região cheia deixa a persistência indisponível.
    #[cfg(feature = "quedas")]
    let compactar_no_boot = !crate::quedas::boot_nao_compacta();
    #[cfg(not(feature = "quedas"))]
    let compactar_no_boot = true;
    if compactar_no_boot && precisa_compactar() {
        let _ = compactar();
    }
    // O registro de boot diz a EK com que este boot falou: a do journal, ou
    // — num journal de antes do 7.7 — a primeira, fixada agora.
    let mut dados = estado::campos(&[&(boots + 1).to_le_bytes()])?;
    dados.extend_from_slice(&entrada_da_chave(&ponto_atual()?)?);
    gravar(tipo::BOOT, &dados)?;
    com(|p| p.boots = boots + 1);
    Ok(Estado::Disponivel)
}

/// Grava um registro, pelo protocolo inteiro: montar, escrever,
/// descarregar, avançar o contador, confirmar. A geração que ele leva quem
/// dá é o journal, pelo tipo: um registro de operação sobe um.
///
/// O registro leva também a auditoria que falta gravar — ver
/// [`gravar_sozinho`].
///
/// Uma falha em qualquer passo deixa a persistência indisponível: o que
/// está no disco e o que o TPM diz podem ter ficado a um passo um do outro,
/// e só o próximo boot, pelo julgamento, sabe resolver isso com segurança.
fn gravar(tipo_do_registro: u16, dados: &[u8]) -> Result<(), &'static str> {
    gravar_com_a_decisao(tipo_do_registro, dados, 0)
}

/// [`gravar`], exigindo que o registro `decisao` da auditoria vá junto —
/// ou antes, num registro só de auditoria. Zero não exige nada.
fn gravar_com_a_decisao(
    tipo_do_registro: u16,
    dados: &[u8],
    decisao: u64,
) -> Result<(), &'static str> {
    let resultado = em_ordem(|| gravar_sozinho(tipo_do_registro, dados, decisao));
    if let Err(motivo) = resultado {
        com(|p| p.estado = Estado::Indisponivel("uma gravacao no journal falhou"));
        crate::log_error!("persistencia", "a gravacao falhou: {}", motivo);
    }
    resultado
}

/// A auditoria que falta gravar, como campos de conteúdo de registro que
/// cabem em `orcamento` bytes.
struct DaAuditoria {
    campos: Vec<u8>,
    /// A última sequência que os campos levam; a já gravada, sem nenhum.
    ate: u64,
    /// O elo dela.
    elo: [u8; 32],
    /// As sequências que saíram do anel antes de chegar ao journal.
    perdidas: Option<(u64, u64)>,
}

/// Só os registros de sequência menor que `antes_de` entram — a lacuna, se
/// houver, sempre.
fn auditoria_que_cabe(orcamento: usize, antes_de: u64) -> Result<DaAuditoria, &'static str> {
    use politica::auditoria::codificar;
    let gravada = auditoria_gravada();
    let elo_gravado = crate::arch::sem_interrupcoes(|| *ELO_GRAVADO.lock());
    let campo = |campos: &mut Vec<u8>, e: Vec<u8>| -> Result<bool, &'static str> {
        if campos.len() + 2 + e.len() > orcamento {
            return Ok(false);
        }
        campos.extend_from_slice(&estado::campos(&[&e])?);
        Ok(true)
    };
    crate::autorizacao::com_auditoria(|c| {
        let falta = c.a_gravar(gravada);
        let mut d = DaAuditoria {
            campos: Vec::new(),
            ate: gravada,
            elo: elo_gravado,
            perdidas: None,
        };
        if let Some(l) = falta.lacuna {
            let e = entrada(
                tipo::AUDITORIA_LACUNA,
                &[&l.primeira.to_le_bytes(), &l.ultima.to_le_bytes(), &l.elo],
            )?;
            if !campo(&mut d.campos, e)? {
                return Ok(d);
            }
            d.ate = l.ultima;
            d.elo = l.elo;
            d.perdidas = Some((l.primeira, l.ultima));
        }
        for r in falta.registros.into_iter().take_while(|r| r.seq < antes_de) {
            let e = entrada(tipo::AUDITORIA_EVENTO, &[&codificar(r.seq, &r.evento)])?;
            if !campo(&mut d.campos, e)? {
                break;
            }
            d.ate = r.seq;
            d.elo = r.elo;
        }
        Ok(d)
    })
    .unwrap_or(Ok(DaAuditoria {
        campos: Vec::new(),
        ate: gravada,
        elo: elo_gravado,
        perdidas: None,
    }))
}

/// Quanto da auditoria um registro leva, no máximo, em bytes. Um registro
/// cabe inteiro no heap algumas vezes — montado, cifrado, lido de volta —,
/// e o heap do kernel é pequeno: um registro de 64 KiB por causa da
/// auditoria seria pedir demais a ele. O resto vai no registro seguinte,
/// ou em registros só de auditoria antes deste.
pub const MAIOR_AUDITORIA_POR_REGISTRO: usize = 16 * 1024;

/// Grava um registro com a auditoria que falta gravar.
///
/// Tudo o que a auditoria registrou antes de a gravação começar vai neste
/// registro, ou antes dele: se não couber junto com o conteúdo, os mais
/// antigos vão antes, em registros só de auditoria. Assim o journal tem a
/// auditoria na ordem da cadeia, e a decisão de uma operação nunca fica
/// para depois dela.
///
/// A `decisao`, se há uma, vai **neste** registro, e nunca num anterior:
/// a mudança e a decisão entram juntas, ou nenhuma entra. A gravação falha
/// se ela não cabe junto com o conteúdo, ou se saiu do anel antes de
/// chegar aqui — mais de um anel inteiro de registros entre ela e a
/// gravação.
fn gravar_sozinho(tipo_do_registro: u16, dados: &[u8], decisao: u64) -> Result<(), &'static str> {
    // Sem decisão, tudo o que veio antes da gravação; com ela, até ela — o
    // que outro fio registrou depois dela pode ir no registro seguinte.
    let exigir = if decisao == 0 {
        crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0)
    } else {
        decisao
    };
    let perdida = |a: &DaAuditoria| {
        a.perdidas
            .is_some_and(|(primeira, ultima)| (primeira..=ultima).contains(&decisao))
    };
    loop {
        let junto = diario::MAIOR_CONTEUDO
            .saturating_sub(dados.len())
            .min(MAIOR_AUDITORIA_POR_REGISTRO);
        let a = auditoria_que_cabe(junto, u64::MAX)?;
        if perdida(&a) {
            return Err("a decisao da operacao saiu da auditoria antes de chegar ao journal");
        }
        if a.ate >= exigir {
            // Só auditoria, e nada dela pendente: não há o que gravar.
            if tipo_do_registro == tipo::AUDITORIA && dados.is_empty() && a.campos.is_empty() {
                return Ok(());
            }
            let mut conteudo = Vec::with_capacity(dados.len() + a.campos.len());
            conteudo.extend_from_slice(dados);
            conteudo.extend_from_slice(&a.campos);
            let gravado = gravar_um(tipo_do_registro, &conteudo);
            // O conteúdo pode ter o corpo de uma mensagem.
            politica::sigiloso::zerar_bloco(&mut conteudo);
            gravado?;
            auditoria_foi_gravada(a.ate, a.elo);
            return Ok(());
        }
        // Não cabe junto: os mais antigos vão antes, num registro só deles,
        // com o teto inteiro — e sem a decisão, que é deste registro.
        let limite = if decisao == 0 { u64::MAX } else { decisao };
        let antes = auditoria_que_cabe(MAIOR_AUDITORIA_POR_REGISTRO, limite)?;
        if perdida(&antes) {
            return Err("a decisao da operacao saiu da auditoria antes de chegar ao journal");
        }
        if antes.campos.is_empty() {
            return Err("a decisao da operacao nao cabe no registro dela");
        }
        gravar_um(tipo::AUDITORIA, &antes.campos)?;
        auditoria_foi_gravada(antes.ate, antes.elo);
    }
}

/// Grava o que a auditoria registrou e ainda não está no journal, num
/// registro só dela. Sem a persistência disponível, nada: a auditoria
/// continua só em memória.
pub fn gravar_auditoria() -> Result<(), &'static str> {
    em_ordem(|| {
        if estado() != Estado::Disponivel {
            return Ok(());
        }
        let ultima = crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0);
        if ultima <= auditoria_gravada() {
            return Ok(());
        }
        gravar(tipo::AUDITORIA, &[])
    })
}

/// De quanto em quanto tempo o coletor grava a auditoria pendente, em ms
/// desde o boot. É a janela do que uma queda de energia pode levar: as
/// leituras e as recusas dos últimos segundos. Uma mudança de estado leva
/// a sua auditoria no próprio registro, e não espera.
pub const INTERVALO_DA_AUDITORIA_MS: u64 = 2_000;

/// Com tantos registros esperando, o coletor grava sem esperar o
/// intervalo: metade do anel, para nenhum sair dele antes do disco.
const AUDITORIA_QUE_NAO_ESPERA: u64 = crate::autorizacao::CAPACIDADE_DA_AUDITORIA as u64 / 2;

/// Só na suíte: o coletor deixa de gravar a auditoria sozinho. A suíte
/// conta registros, e um registro de auditoria no meio de um caso mudaria
/// a conta; os casos que o querem pedem [`gravar_auditoria`].
#[cfg(feature = "modo-teste")]
static AUDITORIA_PAUSADA: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Só para a suíte: pausa ou solta a gravação periódica da auditoria.
#[cfg(feature = "modo-teste")]
pub fn pausar_a_auditoria_de_teste(pausada: bool) {
    AUDITORIA_PAUSADA.store(pausada, Ordering::Release);
}

/// Chamada pelo coletor: grava a auditoria pendente a cada
/// [`INTERVALO_DA_AUDITORIA_MS`], ou antes, se ela já ocupa meio anel.
pub fn gravar_auditoria_se_preciso() {
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    #[cfg(feature = "modo-teste")]
    if AUDITORIA_PAUSADA.load(Ordering::Acquire) {
        return;
    }
    if estado() != Estado::Disponivel {
        return;
    }
    let agora = crate::tempo::uptime_ms();
    let pendentes = crate::autorizacao::com_auditoria(|c| c.ultima_seq())
        .unwrap_or(0)
        .saturating_sub(auditoria_gravada());
    if pendentes == 0 {
        return;
    }
    if pendentes < AUDITORIA_QUE_NAO_ESPERA
        && agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < INTERVALO_DA_AUDITORIA_MS
    {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    let _ = gravar_auditoria();
}

// ---------------------------------------------------------------------------
// A compactação
// ---------------------------------------------------------------------------

/// Com a região ocupada daqui para cima, em quartos, o coletor e o boot
/// compactam: o quarto que sobra é a folga de quem grava entre um olhar do
/// coletor e o seguinte.
const COMPACTAR_A_PARTIR_DE_QUARTOS: u64 = 3;

/// Depois de uma base que não coube na outra região, quantos registros
/// esperar antes de tentar de novo: o estado só diminui com operações, e
/// tentar a cada olhar do coletor seria ler a região inteira à toa.
const ESPERAR_DEPOIS_DE_NAO_CABER: u64 = 64;

/// Os registros da região quando a última base não coube; `u64::MAX` sem
/// nenhuma.
static NAO_COUBE_EM: AtomicU64 = AtomicU64::new(u64::MAX);

/// Só na suíte: o coletor não compacta sozinho. A suíte conta registros e
/// lê a região; os casos que querem a compactação a pedem.
#[cfg(feature = "modo-teste")]
static COMPACTACAO_PAUSADA: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Por que uma compactação não aconteceu.
enum FalhaDaCompactacao {
    /// Não era a hora — havia mudança por gravar —, e nada mudou.
    Adiada(&'static str),
    /// A base não cabe na outra região. A região atual continua a do
    /// journal, inteira e ancorada.
    NaoCabe,
    /// O disco ou o TPM falharam no meio: como numa gravação, só o próximo
    /// boot sabe resolver com segurança.
    Falhou(&'static str),
}

impl From<&'static str> for FalhaDaCompactacao {
    fn from(m: &'static str) -> Self {
        FalhaDaCompactacao::Falhou(m)
    }
}

/// Se a região passou do ponto de compactar.
fn precisa_compactar() -> bool {
    com(|p| {
        let Some(a) = p.aberta.as_ref() else {
            return false;
        };
        let (usados, total) = a.escritor.ocupacao();
        let nao_coube = NAO_COUBE_EM.load(Ordering::Acquire);
        p.estado == Estado::Disponivel
            && usados * 4 >= total * COMPACTAR_A_PARTIR_DE_QUARTOS
            && (nao_coube == u64::MAX || p.registros >= nao_coube + ESPERAR_DEPOIS_DE_NAO_CABER)
    })
}

/// Chamada pelo coletor: compacta se a região passou do ponto.
///
/// O coletor é um ponto seguro: ele não está no meio de operação nenhuma,
/// e com a ordem das gravações na mão nenhuma outra está — o que está em
/// memória é exatamente o que está no journal.
pub fn compactar_se_preciso() {
    #[cfg(feature = "modo-teste")]
    if COMPACTACAO_PAUSADA.load(Ordering::Acquire) {
        return;
    }
    #[cfg(feature = "quedas")]
    if crate::quedas::coletor_nao_compacta() {
        return;
    }
    if !precisa_compactar() {
        return;
    }
    em_ordem(|| {
        if precisa_compactar() {
            let _ = compactar();
        }
    });
}

/// Compacta, e diz o desfecho na auditoria. Uma falha do disco ou do TPM
/// deixa a persistência indisponível, como a de qualquer gravação; uma base
/// que não cabe, não — a região atual continua valendo, e o que não couber
/// nela falha quando for gravado.
fn compactar() -> Result<(), &'static str> {
    let resultado = em_ordem(compactar_sozinho);
    let (codigo, detalhe, r) = match resultado {
        Ok((regiao, registros, ancora, n)) => {
            NAO_COUBE_EM.store(u64::MAX, Ordering::Release);
            crate::log_info!(
                "persistencia",
                "compactado na regiao {}: {} registros, ancora {}",
                regiao,
                registros,
                ancora
            );
            (
                politica::Codigo::Allow,
                alloc::format!(
                    "regiao {regiao}; {registros} registros; ancora {ancora}; compactacao {n}"
                ),
                Ok(()),
            )
        }
        Err(FalhaDaCompactacao::Adiada(m)) => {
            crate::log_info!("persistencia", "compactacao adiada: {}", m);
            return Err(m);
        }
        Err(FalhaDaCompactacao::NaoCabe) => {
            NAO_COUBE_EM.store(com(|p| p.registros), Ordering::Release);
            crate::log_error!(
                "persistencia",
                "a compactacao nao cabe na outra regiao: o journal continua onde esta"
            );
            (
                politica::Codigo::Error,
                alloc::string::String::from("a base nao cabe na outra regiao"),
                Err("a base nao cabe na outra regiao"),
            )
        }
        Err(FalhaDaCompactacao::Falhou(m)) => {
            com(|p| p.estado = Estado::Indisponivel("uma compactacao do journal falhou"));
            crate::log_error!("persistencia", "a compactacao falhou: {}", m);
            (
                politica::Codigo::Error,
                alloc::string::String::from(m),
                Err(m),
            )
        }
    };
    crate::autorizacao::auditar_do_kernel("persistence.compact", "", codigo, &detalhe);
    r
}

/// O tipo de uma entrada.
fn tipo_da_entrada(e: &[u8]) -> Option<u16> {
    let campos = estado::ler_campos(e).ok()?;
    let t: [u8; 2] = (*campos.first()?).try_into().ok()?;
    Some(u16::from_le_bytes(t))
}

/// As entradas que mudam o estado de autoridade, e o marcador da operação:
/// o que a base carrega da região velha, na ordem em que aconteceu.
fn e_de_autoridade(t: u16) -> bool {
    matches!(
        t,
        tipo::OPERACAO
            | tipo::AGENTE_REGISTRADO
            | tipo::AGENTE_REVOGADO
            | tipo::PAPEL_ATRIBUIDO
            | tipo::POLITICA
            | tipo::PESSOA_REGISTRADA
            | tipo::PESSOA_REVOGADA
            | tipo::CREDENCIAL_ROTACIONADA
            | tipo::SESSAO_REVOGADA
            | tipo::LAPIDE
    )
}

/// O que a base leva de um registro da região velha, como um grupo — que
/// vai inteiro numa parte só.
///
/// - De uma operação: as mudanças de autoridade, o marcador, e a decisão
///   que a autorizou — os registros da auditoria com o método da operação,
///   como [`tipo::AUDITORIA_HISTORICA`]. A mudança não fica no journal sem
///   a decisão dela, nem depois de compactada.
/// - De uma parte de uma base anterior: o que ela já carregava — as
///   mudanças e as decisões delas, juntas como estavam.
/// - Do resto — boots, auditoria, mensagens —, nada: o estado das
///   mensagens e a cadeia da auditoria a base tira da memória.
///
/// A política vai só uma vez: a do último registro que a tem, que é a que
/// vigora.
fn grupo_da_base(
    r: &diario::Registro,
    ultima_politica: Option<u64>,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let fica = |t: u16| t != tipo::POLITICA || ultima_politica == Some(r.sequencia);
    let mut grupo = Vec::new();
    match r.tipo {
        tipo::BASE => {
            for e in entradas(r)? {
                let t = tipo_da_entrada(e).ok_or("entrada sem tipo")?;
                if (e_de_autoridade(t) && fica(t)) || t == tipo::AUDITORIA_HISTORICA {
                    grupo.push(e.to_vec());
                }
            }
        }
        tipo::OPERACAO => {
            let todas = entradas(r)?;
            let nome = todas
                .first()
                .and_then(|e| estado::ler_campos(e).ok())
                .and_then(|c| c.get(1).copied())
                .unwrap_or(&[]);
            for e in &todas {
                let t = tipo_da_entrada(e).ok_or("entrada sem tipo")?;
                if e_de_autoridade(t) && fica(t) {
                    grupo.push(e.to_vec());
                } else if t == tipo::AUDITORIA_EVENTO {
                    let campos = estado::ler_campos(e)?;
                    let codificado = campos.get(1).ok_or("auditoria sem registro")?;
                    let (_, ev) = politica::auditoria::decodificar(codificado)?;
                    if ev.metodo.as_bytes() == nome {
                        grupo.push(entrada(tipo::AUDITORIA_HISTORICA, &[codificado])?);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(grupo)
}

/// A base sendo escrita na outra região: os grupos vão juntando numa parte
/// até ela encher, e cada parte cheia vai ao disco — sem descarga, que é
/// uma só, no fim.
struct EscritaDaBase<'a> {
    base: diario::Base,
    destino: &'a mut Particao,
    chave: [u8; 32],
    versao: u64,
    tempo: u64,
    parte: Vec<u8>,
    partes: u64,
}

impl EscritaDaBase<'_> {
    fn grupo(&mut self, grupo: &[Vec<u8>]) -> Result<(), FalhaDaCompactacao> {
        let tamanho: usize = grupo.iter().map(|e| e.len() + 2).sum();
        if tamanho > diario::MAIOR_CONTEUDO {
            return Err(FalhaDaCompactacao::Falhou(
                "um grupo da base nao cabe num registro",
            ));
        }
        if self.parte.len() + tamanho > diario::MAIOR_CONTEUDO {
            self.selar()?;
        }
        for e in grupo {
            self.parte.extend_from_slice(&estado::campos(&[e])?);
        }
        Ok(())
    }

    fn selar(&mut self) -> Result<(), FalhaDaCompactacao> {
        if self.parte.is_empty() {
            return Ok(());
        }
        let n = nonce()?;
        let parte = self
            .base
            .parte(&self.chave, n, self.versao, self.tempo, &self.parte)
            .map_err(nao_cabe)?;
        // A parte pode ter o corpo de uma mensagem.
        politica::sigiloso::zerar_bloco(&mut self.parte);
        self.parte.clear();
        self.destino.escrever(parte.setor, &parte.bytes)?;
        self.partes += 1;
        #[cfg(feature = "quedas")]
        if self.partes == 1 {
            crate::quedas::aqui(crate::quedas::Ponto::DepoisDaPrimeiraParte);
        }
        Ok(())
    }
}

/// A partição cheia, para a base, é a base que não cabe.
fn nao_cabe(m: &'static str) -> FalhaDaCompactacao {
    if m == "a particao de estado esta cheia" {
        FalhaDaCompactacao::NaoCabe
    } else {
        FalhaDaCompactacao::Falhou(m)
    }
}

/// A compactação, com a ordem das gravações na mão. Devolve a região nova,
/// quantos registros a base tem, a âncora dela e quantas compactações o
/// journal já teve.
///
/// # O protocolo
///
/// 1. A base inteira vai para a **outra** região: o histórico de autoridade
///    da região atual com as decisões, o estado das mensagens e o ponto de
///    onde a cadeia da auditoria continua — e o fecho. Tudo com a mesma
///    âncora, a seguinte.
/// 2. Uma descarga.
/// 3. O contador avança, uma vez.
/// 4. Só então o journal passa a ser o da região nova.
///
/// Até o passo 3, a região atual é a do journal — uma queda em qualquer
/// ponto deixa a base sem fecho, ou com o fecho e sem o contador; no
/// primeiro caso ela não vale, no segundo o boot completa o avanço, como o
/// de qualquer registro. Depois do 3, a região velha é um disco anterior ao
/// que o TPM viu: nunca mais é escolhida, e devolvida ao disco sozinha é
/// recusada.
///
/// # Só num ponto seguro
///
/// O estado das mensagens vem da memória, e o da memória tem de ser o do
/// journal: nenhuma operação no meio, nenhuma mudança anotada por gravar.
/// O coletor e o boot chamam daqui; uma operação, nunca — a base levaria
/// uma mudança sem a decisão dela.
fn compactar_sozinho() -> Result<(usize, u64, u64, u64), FalhaDaCompactacao> {
    use FalhaDaCompactacao::*;
    if crate::arch::sem_interrupcoes(|| !PENDENTES.lock().is_empty()) {
        return Err(Adiada("ha mudancas de mensagem por gravar"));
    }
    let (estado, regiao, instalacao, boots, compactacoes) =
        com(|p| (p.estado, p.regiao, p.instalacao, p.boots, p.compactacoes));
    if estado != Estado::Disponivel {
        return Err(Adiada(estado.motivo()));
    }
    let instalacao = instalacao.ok_or(Falhou("o journal nao tem a instalacao"))?;
    let (chave, _) = segredos().ok_or(Falhou("sem a chave do Duke"))?;
    duravel()?;
    let [a, b] = regioes()?;
    let (mut origem, mut destino) = if regiao == 0 { (a, b) } else { (b, a) };
    let base = com(|p| {
        p.aberta
            .as_ref()
            .ok_or("a persistencia nao esta aberta")
            .and_then(|a| a.escritor.base(destino.setores))
    })?;
    #[cfg(feature = "quedas")]
    crate::quedas::gravacao_comecou(tipo::BASE_FIM);
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::AntesDaEscrita);

    let interrompido = |e: diario::Interrompido<FalhaDaCompactacao>| match e {
        diario::Interrompido::Meio(m) => Falhou(m),
        diario::Interrompido::Recusado { motivo, .. } => motivo,
    };
    // A primeira passada: de qual registro é a política que vigora.
    let mut ultima_politica = None;
    diario::percorrer(&mut origem, &chave, |r| {
        let tem = entradas(&r)
            .map_err(Falhou)?
            .iter()
            .any(|e| tipo_da_entrada(e) == Some(tipo::POLITICA));
        if tem {
            ultima_politica = Some(r.sequencia);
        }
        Ok(())
    })
    .map_err(interrompido)?;

    let mut escrita = EscritaDaBase {
        base,
        destino: &mut destino,
        chave,
        versao: crate::autorizacao::versao_da_politica(),
        tempo: agora(),
        parte: Vec::new(),
        partes: 0,
    };
    // A segunda: o histórico de autoridade, com as decisões.
    diario::percorrer(&mut origem, &chave, |r| {
        let grupo = grupo_da_base(&r, ultima_politica).map_err(Falhou)?;
        if grupo.is_empty() {
            Ok(())
        } else {
            escrita.grupo(&grupo)
        }
    })
    .map_err(interrompido)?;

    // As mensagens, da memória: as lápides, as vivas na ordem dos ids, e o
    // próximo id.
    let mut grupos = crate::mensagens::com_as_caixas(|c| -> Result<_, &'static str> {
        let mut g: Vec<Vec<Vec<u8>>> = Vec::new();
        for l in c.lapides() {
            g.push(alloc::vec![entrada(
                tipo::MENSAGEM_LAPIDE,
                &[
                    &l.id.to_le_bytes(),
                    &l.de.bytes(),
                    &l.para.bytes(),
                    &[l.estado.codigo()],
                    &l.versao.to_le_bytes(),
                ],
            )?]);
        }
        for m in c.todas() {
            let mut viva = alloc::vec![entrada_criada(m.gravada())?];
            if m.estado == politica::mensagens::Estado::Entregue {
                viva.push(entrada(
                    tipo::MENSAGEM_ESTADO,
                    &[
                        &m.id.to_le_bytes(),
                        &[m.estado.codigo()],
                        &m.versao.to_le_bytes(),
                    ],
                )?);
            }
            g.push(viva);
        }
        g.push(alloc::vec![entrada(
            tipo::MENSAGENS_PROXIMO,
            &[&c.proximo().to_le_bytes()]
        )?]);
        Ok(g)
    })?;
    // O armazém, da memória: cada arquivo, na ordem das versões — a ordem
    // em que o boot os aplica, que só aceita versões crescentes —, e a
    // próxima versão, para as já dadas não voltarem.
    grupos.extend(crate::armazem::com_o_armazem(
        |a| -> Result<_, &'static str> {
            let mut arquivos: Vec<(&str, &::armazem::Objeto)> = a.todos().collect();
            arquivos.sort_unstable_by_key(|(_, o)| o.versao());
            let mut g: Vec<Vec<Vec<u8>>> = Vec::new();
            for (caminho, o) in arquivos {
                g.push(alloc::vec![entrada(
                    tipo::ARQUIVO_GRAVADO,
                    &[caminho.as_bytes(), &o.versao().to_le_bytes(), o.dados()],
                )?]);
            }
            g.push(alloc::vec![entrada(
                tipo::ARMAZEM_PROXIMO,
                &[&a.proxima().to_le_bytes()]
            )?]);
            Ok(g)
        },
    )?);
    let mut escritas = Ok(());
    for g in &grupos {
        escritas = escrita.grupo(g);
        if escritas.is_err() {
            break;
        }
    }
    for g in grupos.iter_mut().flatten() {
        politica::sigiloso::zerar_bloco(g);
    }
    escritas?;

    // A auditoria: o que está no journal e o anel ainda tem vai inteiro; a
    // cadeia continua do elo de antes do primeiro deles — ou do último
    // gravado, se o anel já não tem nenhum.
    let gravada = auditoria_gravada();
    let elo_gravado = crate::arch::sem_interrupcoes(|| *ELO_GRAVADO.lock());
    let auditoria = crate::autorizacao::com_auditoria(|c| -> Result<_, &'static str> {
        let no_anel: Vec<&politica::auditoria::Registro> = c
            .ultimos(crate::autorizacao::CAPACIDADE_DA_AUDITORIA)
            .filter(|r| r.seq <= gravada)
            .collect();
        let (antes, elo) = match no_anel.first() {
            Some(f) => (f.seq - 1, f.anterior),
            None => (gravada, elo_gravado),
        };
        let mut g = Vec::new();
        if antes >= 1 {
            g.push(alloc::vec![entrada(
                tipo::AUDITORIA_COMPACTADA,
                &[&1u64.to_le_bytes(), &antes.to_le_bytes(), &elo],
            )?]);
        }
        for r in no_anel {
            g.push(alloc::vec![entrada(
                tipo::AUDITORIA_EVENTO,
                &[&politica::auditoria::codificar(r.seq, &r.evento)],
            )?]);
        }
        Ok(g)
    })
    .unwrap_or(Ok(Vec::new()))?;
    for g in &auditoria {
        escrita.grupo(g)?;
    }
    escrita.selar()?;

    // O fecho.
    let partes = escrita.partes;
    let n = nonce()?;
    let fechada = escrita
        .base
        .fechar(
            &chave,
            n,
            escrita.versao,
            escrita.tempo,
            &estado::campos(&[
                &instalacao,
                &boots.to_le_bytes(),
                &(compactacoes + 1).to_le_bytes(),
                &ponto_atual()?,
            ])?,
        )
        .map_err(nao_cabe)?;
    destino.escrever(fechada.setor, &fechada.bytes)?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDaEscrita);
    destino.descarregar()?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDaDescarga);
    let ancora_da_base = fechada.ancora;
    // Só depois de a base inteira estar descarregada o contador anda.
    // Se o TPM falhar e não tiver andado, a base fica na outra região sem
    // âncora: o boot seguinte a completa — é o mesmo estado — ou a deixa,
    // se o contador nunca chegar a ela. Nada se desfaz aqui.
    let avancado = match avancar_a_ancora(ancora_da_base) {
        Avanco::Feito(v) => v,
        Avanco::NaoAndou(m) | Avanco::Incerto(m) => return Err(Falhou(m)),
    };
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDoContador);
    // Na suíte: o contador devolve outro valor que o da base — como se
    // alguém mais o tivesse avançado.
    #[cfg(feature = "modo-teste")]
    let avancado = if CONTADOR_TROCADO.swap(false, Ordering::AcqRel) {
        avancado.wrapping_add(1)
    } else {
        avancado
    };
    let escritor = fechada.confirmar(avancado)?;
    let nova = 1 - regiao;
    com(|p| {
        if let Some(a) = p.aberta.as_mut() {
            a.escritor = escritor;
        }
        p.regiao = nova;
        p.registros = partes + 1;
        p.registros_de_auditoria = 0;
        p.compactacoes = compactacoes + 1;
    });
    Ok((nova, partes + 1, ancora_da_base, compactacoes + 1))
}

/// O que aconteceu com um avanço do contador.
enum Avanco {
    /// Andou, e vale isto — lido de volta, pela sessão.
    Feito(u64),
    /// Não andou: uma leitura autenticada diz que ele está onde estava.
    NaoAndou(&'static str),
    /// Não se sabe: nem o avanço nem a leitura de conferência responderam.
    Incerto(&'static str),
}

/// Avança o contador da âncora, que tem de chegar a `esperado`: o
/// incremento e a leitura de volta, pela sessão autenticada.
///
/// Uma falha no meio não diz se o contador andou — o incremento pode ter
/// acontecido e a resposta se perdido, ou chegado adulterada. Uma leitura
/// autenticada, por uma sessão nova, diz: se ele está em `esperado`,
/// andou; se está um antes, não andou. Um valor que o TPM mostra sem a
/// sessão conferir não decide nada.
fn avancar_a_ancora(esperado: u64) -> Avanco {
    let avanco = com_a_ancora(|a, t| {
        a.incrementar(t, &mut Sorteio)?;
        #[cfg(feature = "quedas")]
        crate::quedas::aqui(crate::quedas::Ponto::DepoisDoIncremento);
        a.ler(t, &mut Sorteio)
    });
    let erro = match avanco {
        Ok(v) => return Avanco::Feito(v),
        Err(e) => e.motivo(),
    };
    crate::log_warn!(
        "persistencia",
        "o avanco do contador falhou ({}): conferindo pela leitura",
        erro
    );
    match com_a_ancora(|a, t| a.ler(t, &mut Sorteio)) {
        Ok(v) if v == esperado => Avanco::Feito(v),
        Ok(v) if v.checked_add(1) == Some(esperado) => Avanco::NaoAndou(erro),
        Ok(_) => Avanco::Incerto("o contador do TPM nao esta onde o journal espera"),
        Err(e) => Avanco::Incerto(e.motivo()),
    }
}

/// Chama `f` com a âncora aberta e o TPM.
fn com_a_ancora<R>(
    f: impl FnOnce(&mut ancora::Ancora, &mut crate::tpm::Interface) -> Result<R, ancora::Erro>,
) -> Result<R, ancora::Erro> {
    crate::tpm::com_o_tpm(|t| {
        com(|p| p.aberta.as_mut().map(|a| f(&mut a.ancora, t)))
            .ok_or(ancora::Erro::Transporte("a persistencia nao esta aberta"))?
    })
    .ok_or(ancora::Erro::Transporte("sem TPM"))?
}

/// O protocolo de um registro: montar, escrever, descarregar, avançar o
/// contador, confirmar.
fn gravar_um(tipo_do_registro: u16, dados: &[u8]) -> Result<(), &'static str> {
    #[cfg(feature = "quedas")]
    crate::quedas::gravacao_comecou(tipo_do_registro);
    let tempo = agora();
    let versao = crate::autorizacao::versao_da_politica();
    let n = nonce()?;
    let montado = com(|p| {
        if p.estado != Estado::Disponivel {
            return Err(p.estado.motivo());
        }
        let a = p.aberta.as_ref().ok_or("a persistencia nao esta aberta")?;
        a.escritor.montar(
            &a.chave,
            n,
            &Conteudo {
                tipo: tipo_do_registro,
                versao_da_politica: versao,
                tempo,
                dados,
            },
        )
    })?;
    let mut meio = particao(com(|p| p.regiao))?;
    // A falha provocada pela suíte é a do disco, no lugar da escrita: o
    // caso confere que, quando a escrita não acontece, o contador também
    // não andou.
    #[cfg(feature = "modo-teste")]
    if FALHAR_A_PROXIMA.swap(false, Ordering::AcqRel) {
        return Err("falha de gravacao provocada pela suite");
    }
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::AntesDaEscrita);
    meio.escrever(montado.setor, &montado.bytes)?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDaEscrita);
    meio.descarregar()?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDaDescarga);
    // Um registro só de auditoria não avança o contador: o tipo decide, no
    // journal, e o escritor só o confirma sem contador. O resto avança —
    // só depois de descarregado: um contador à frente do disco seria um
    // disco que parece velho no próximo boot.
    if !montado.avanca() {
        #[cfg(feature = "quedas")]
        crate::quedas::aqui(crate::quedas::Ponto::DepoisDoContador);
        return com(|p| {
            p.aberta
                .as_mut()
                .ok_or("a persistencia nao esta aberta")?
                .escritor
                .confirmar_sem_contador(&montado)?;
            p.registros += 1;
            p.registros_de_auditoria += 1;
            Ok(())
        });
    }
    let avancado = match avancar_a_ancora(montado.ancora) {
        Avanco::Feito(v) => v,
        // O registro está no disco, e o contador, conferido por uma
        // leitura autenticada, não andou: o TPM recusou — uma credencial
        // inválida, por exemplo. Desfeito, o registro não existe, e a
        // operação falhou de verdade: o próximo boot não a completa.
        Avanco::NaoAndou(m) => {
            crate::log_error!("persistencia", "o contador nao andou: {}", m);
            let zero = [0u8; diario::TAM_SETOR];
            return match meio
                .escrever(montado.setor, &zero)
                .and_then(|()| meio.descarregar())
            {
                Ok(()) => Err("o TPM nao avancou o contador, e o registro foi desfeito"),
                Err(_) => Err(
                    "o TPM nao avancou o contador, e o registro nao se desfez: o proximo boot decide",
                ),
            };
        }
        Avanco::Incerto(m) => {
            crate::log_error!("persistencia", "o contador ficou incerto: {}", m);
            return Err("o TPM nao confirmou o avanco do contador: o proximo boot decide");
        }
    };
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::DepoisDoContador);
    com(|p| {
        p.aberta
            .as_mut()
            .ok_or("a persistencia nao esta aberta")?
            .escritor
            .confirmar(&montado, avancado)?;
        p.geracao = montado.geracao;
        p.registros += 1;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// As operações de autoridade
// ---------------------------------------------------------------------------

/// Se o journal foi recusado, por quê.
///
/// Um journal recusado é um disco anterior ao que a âncora confirmou, ou
/// estragado, ou trocado: o que se perdeu dele pode ser uma revogação — de
/// um agente da imagem, de uma pessoa — que o kernel agora não conhece. É
/// a mesma razão do portão administrativo, e o mesmo desfecho: nenhuma
/// credencial é aceita enquanto não se sabe quais foram revogadas. A
/// serial e o `sistema` não têm credencial a revogar, e continuam.
///
/// A persistência só **indisponível** — sem TPM, sem disco durável — não
/// é isso: ali não há prova de que algo se perdeu, e as credenciais
/// continuam, com as mensagens só em memória.
pub fn revogacoes_desconhecidas() -> Option<&'static str> {
    match estado() {
        Estado::Recusada(motivo) => Some(motivo),
        _ => None,
    }
}

/// Uma operação de autoridade pode começar? Só com a persistência
/// disponível. Não há exceção: nem para o `sistema`, nem para a serial.
pub fn exigir() -> Result<(), &'static str> {
    match estado() {
        Estado::Disponivel => Ok(()),
        outro => Err(outro.motivo()),
    }
}

/// O estado de autoridade antes de uma operação: o que ela pode mudar, para
/// gravar a diferença — e desfazer, se a gravação falhar.
pub struct Foto {
    agentes: Vec<crate::identidade::Agente>,
    revogados: Vec<[u8; 32]>,
    politica: String,
    pessoas: Vec<sigilo::pessoas::Pessoa>,
}

impl Foto {
    pub fn tirar() -> Foto {
        Foto {
            agentes: crate::identidade::agentes(),
            revogados: crate::identidade::administradores_revogados(),
            politica: crate::autorizacao::com_politica(|p| p.texto()),
            pessoas: crate::pessoas::todas(),
        }
    }

    /// Volta o estado de autoridade ao da foto: o que a operação concedeu
    /// sai. Só para operações que concedem — ver [`concluir`]: numa que
    /// tira, a foto teria de volta o que foi tirado.
    fn restaurar_concessoes(&self) {
        crate::identidade::restaurar_agentes(&self.agentes);
        if let Ok(p) = politica::arquivo::Politica::ler(&self.politica) {
            crate::autorizacao::restaurar_politica(p);
        }
        crate::pessoas::restaurar(&self.pessoas);
    }
}

/// Grava o que uma operação de autoridade mudou, comparando com a foto de
/// antes dela. `nome` é a operação e `recurso` o que ela disse ter
/// alcançado — vão juntos, para o journal contar o que houve mesmo quando
/// a mudança não deixa rastro no estado (o encerramento de uma sessão).
///
/// Se a gravação falha, o que a operação **concedeu** é desfeito — um
/// agente registrado sai, a política volta — e o que ela **tirou** fica:
/// uma revogação que não ficou gravada continua valendo até o boot, e a
/// persistência indisponível impede que qualquer outra coisa mude até lá.
///
/// `decisao` é o registro da auditoria que autorizou a operação — feito
/// antes desta chamada —, e vai no mesmo registro do journal: uma mudança
/// de autoridade nunca fica no disco sem a decisão que a autorizou.
pub fn concluir(
    foto: &Foto,
    nome: &str,
    recurso: &str,
    desfazer: bool,
    decisao: u64,
) -> Result<(), &'static str> {
    let mut entradas = diferenca(foto, nome, recurso)?;
    // O que a operação fez às mensagens — a revogação de um titular anula
    // as dele — vai no mesmo registro: uma operação, um registro.
    entradas.extend(tirar_pendentes());
    let conteudo = estado::campos(&entradas.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
    match gravar_com_a_decisao(tipo::OPERACAO, &conteudo, decisao) {
        Ok(()) => Ok(()),
        Err(motivo) => {
            if desfazer {
                foto.restaurar_concessoes();
            }
            Err(motivo)
        }
    }
}

/// Uma entrada do registro de uma operação: o tipo e os campos.
fn entrada(t: u16, campos: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let mut todos: Vec<&[u8]> = Vec::with_capacity(campos.len() + 1);
    let t = t.to_le_bytes();
    todos.push(&t);
    todos.extend_from_slice(campos);
    estado::campos(&todos)
}

/// O que mudou entre a foto e agora, como entradas do registro.
fn diferenca(foto: &Foto, nome: &str, recurso: &str) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut v = Vec::new();
    v.push(entrada(
        tipo::OPERACAO,
        &[nome.as_bytes(), recurso.as_bytes()],
    )?);

    let agora = crate::identidade::agentes();
    for a in &agora {
        match foto.agentes.iter().find(|b| b.chave == a.chave) {
            None => {
                let linha = sigilo::registro::linha(&a.chave, &a.nome, a.papel.as_deref());
                v.push(entrada(tipo::AGENTE_REGISTRADO, &[linha.as_bytes()])?);
            }
            Some(b) if b.papel != a.papel => {
                let papel = a.papel.as_deref().unwrap_or("");
                v.push(entrada(
                    tipo::PAPEL_ATRIBUIDO,
                    &[a.nome.as_bytes(), papel.as_bytes()],
                )?);
            }
            Some(_) => {}
        }
    }
    for b in &foto.agentes {
        if !agora.iter().any(|a| a.chave == b.chave) {
            v.push(entrada(tipo::AGENTE_REVOGADO, &[&b.chave])?);
        }
    }

    for chave in crate::identidade::administradores_revogados() {
        if !foto.revogados.contains(&chave) {
            let assinatura = crate::identidade::assinatura_do_administrador(&chave);
            v.push(entrada(
                tipo::LAPIDE,
                &[&chave, assinatura.as_ref().map_or(&[][..], |a| &a[..])],
            )?);
        }
    }

    let politica = crate::autorizacao::com_politica(|p| p.texto());
    if politica != foto.politica {
        v.push(entrada(tipo::POLITICA, &[politica.as_bytes()])?);
    }

    for p in crate::pessoas::todas() {
        match foto.pessoas.iter().find(|q| q.id == p.id) {
            None => {
                let linha = sigilo::pessoas::linha(&p);
                v.push(entrada(tipo::PESSOA_REGISTRADA, &[linha.as_bytes()])?);
            }
            Some(q) if q.estado != p.estado && p.estado == sigilo::pessoas::Estado::Revogada => {
                v.push(entrada(tipo::PESSOA_REVOGADA, &[&p.id.0])?);
            }
            Some(q) if q.credencial != p.credencial => {
                let linha = sigilo::pessoas::linha(&p);
                v.push(entrada(tipo::CREDENCIAL_ROTACIONADA, &[linha.as_bytes()])?);
            }
            Some(_) => {}
        }
    }
    Ok(v)
}

/// Reaplica um registro lido do journal, no boot.
fn reaplicar(r: &diario::Registro) -> Result<(), &'static str> {
    for e in entradas(r)? {
        reaplicar_entrada(e)?;
    }
    Ok(())
}

/// As entradas de um registro. A abertura e o boot têm um campo próprio
/// primeiro; o fecho de uma base, só os campos dele; os outros tipos são
/// só entradas. Em todos os que não são da base, a auditoria que o
/// registro levou vem no fim, como entradas.
fn entradas(r: &diario::Registro) -> Result<Vec<&[u8]>, &'static str> {
    let campos = estado::ler_campos(&r.conteudo)?;
    match r.tipo {
        tipo::ABERTURA | tipo::BOOT => match campos.split_first() {
            Some((_, resto)) => Ok(resto.to_vec()),
            None => Err("registro sem o campo do tipo"),
        },
        tipo::OPERACAO | tipo::MENSAGENS | tipo::ARMAZEM | tipo::AUDITORIA | tipo::BASE => {
            Ok(campos)
        }
        // O fecho tem só os campos dele — ver [`fecho`].
        tipo::BASE_FIM => fecho(&r.conteudo).map(|_| Vec::new()),
        _ => Err("tipo de registro desconhecido"),
    }
}

/// O primeiro campo de um registro de abertura ou de boot.
fn primeiro_campo(conteudo: &[u8]) -> Option<&[u8]> {
    estado::ler_campos(conteudo).ok()?.first().copied()
}

/// Repõe uma entrada da auditoria na cadeia que o journal refaz. Fora do
/// boot não há cadeia sendo refeita, e a entrada só é conferida.
fn repor_na_auditoria(
    f: impl FnOnce(&mut Cadeia) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    crate::arch::sem_interrupcoes(|| match REPOSTA.lock().as_mut() {
        Some(c) => f(c),
        None => Ok(()),
    })
}

fn texto(b: &[u8]) -> Result<&str, &'static str> {
    core::str::from_utf8(b).map_err(|_| "campo que nao e texto")
}

fn chave(b: &[u8]) -> Result<[u8; 32], &'static str> {
    b.try_into().map_err(|_| "chave que nao tem 32 bytes")
}

fn u64_de(b: &[u8]) -> Result<u64, &'static str> {
    b.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| "numero que nao tem 8 bytes")
}

fn dono(b: &[u8]) -> Result<politica::mensagens::Dono, &'static str> {
    politica::mensagens::Dono::de_bytes(b).ok_or("titular de mensagem invalido")
}

/// Reaplica uma entrada de um registro de operação.
pub(crate) fn reaplicar_entrada(e: &[u8]) -> Result<(), &'static str> {
    let campos = estado::ler_campos(e)?;
    let (t, resto) = campos.split_first().ok_or("entrada vazia")?;
    let t: [u8; 2] = (*t).try_into().map_err(|_| "tipo de entrada invalido")?;
    match (u16::from_le_bytes(t), resto) {
        (tipo::OPERACAO, [_nome, _recurso]) => Ok(()),
        (tipo::CHAVE_DO_TPM, [ponto]) => fixar(ponto_da_chave(ponto)?),
        (tipo::AGENTE_REGISTRADO, [linha]) => {
            let linha = texto(linha)?;
            let (k, nome, papel) = match sigilo::registro::ler_linha(linha) {
                Ok(Some(entrada)) => entrada,
                _ => return Err("linha de agente gravada que nao se le"),
            };
            crate::identidade::restaurar_agente(k, nome, papel);
            Ok(())
        }
        (tipo::AGENTE_REVOGADO, [k]) => {
            // Um agente que a imagem já não traz não é erro: a revogação
            // dele já vale.
            let _ = crate::identidade::revogar(&chave(k)?);
            Ok(())
        }
        (tipo::PAPEL_ATRIBUIDO, [nome, papel]) => {
            let _ = crate::identidade::atribuir(texto(nome)?, texto(papel)?);
            Ok(())
        }
        (tipo::POLITICA, [t]) => {
            let p = politica::arquivo::Politica::ler(texto(t)?)
                .map_err(|_| "a politica gravada nao vale")?;
            crate::autorizacao::restaurar_politica(p);
            Ok(())
        }
        (tipo::PESSOA_REGISTRADA | tipo::CREDENCIAL_ROTACIONADA, [linha]) => {
            let p = match sigilo::pessoas::ler_linha(texto(linha)?) {
                Ok(Some(p)) => p,
                _ => return Err("linha de pessoa gravada que nao se le"),
            };
            crate::pessoas::restaurar_pessoa(p);
            Ok(())
        }
        (tipo::PESSOA_REVOGADA, [id]) => {
            let id: [u8; 8] = (*id)
                .try_into()
                .map_err(|_| "identificador de pessoa invalido")?;
            let _ = crate::pessoas::revogar_pessoa(sigilo::pessoas::IdPessoa(id));
            Ok(())
        }
        (tipo::LAPIDE, [k, _assinatura]) => {
            crate::identidade::aplicar_lapide(&chave(k)?);
            Ok(())
        }
        (tipo::MENSAGEM_CRIADA, [id, de, para, criada, expira, corpo]) => {
            crate::mensagens::restaurar(politica::mensagens::Gravada {
                id: u64_de(id)?,
                de: dono(de)?,
                para: dono(para)?,
                corpo,
                criada_ms: u64_de(criada)?,
                expira_ms: u64_de(expira)?,
            })
        }
        (tipo::MENSAGEM_ESTADO, [id, estado, versao]) => {
            let estado = match estado {
                [c] => politica::mensagens::Estado::de_codigo(*c),
                _ => None,
            }
            .ok_or("estado de mensagem invalido")?;
            crate::mensagens::aplicar(u64_de(id)?, estado, u64_de(versao)?)
        }
        (tipo::AUDITORIA_EVENTO, [r]) => {
            let (seq, evento) = politica::auditoria::decodificar(r)?;
            repor_na_auditoria(|c| c.repor(seq, evento))
        }
        (tipo::AUDITORIA_COMPACTADA, [primeira, ultima, elo]) => {
            let l = politica::auditoria::Lacuna {
                primeira: u64_de(primeira)?,
                ultima: u64_de(ultima)?,
                elo: chave(elo)?,
            };
            repor_na_auditoria(|c| c.pular(l))
        }
        (tipo::AUDITORIA_HISTORICA, [r]) => politica::auditoria::decodificar(r).map(|_| ()),
        (tipo::MENSAGEM_LAPIDE, [id, de, para, estado, versao]) => {
            let estado = match estado {
                [c] => politica::mensagens::Estado::de_codigo(*c),
                _ => None,
            }
            .ok_or("estado de mensagem invalido")?;
            crate::mensagens::restaurar_lapide(politica::mensagens::Lapide {
                id: u64_de(id)?,
                de: dono(de)?,
                para: dono(para)?,
                estado,
                versao: u64_de(versao)?,
            })
        }
        (tipo::MENSAGENS_PROXIMO, [n]) => crate::mensagens::fixar_proximo(u64_de(n)?),
        (tipo::ARQUIVO_GRAVADO, [caminho, versao, dados]) => {
            crate::armazem::restaurar(&::armazem::Mudanca::Gravado {
                caminho: String::from(texto(caminho)?),
                versao: u64_de(versao)?,
                dados: dados.to_vec(),
            })
        }
        (tipo::ARQUIVO_APAGADO, [caminho, versao]) => {
            crate::armazem::restaurar(&::armazem::Mudanca::Apagado {
                caminho: String::from(texto(caminho)?),
                versao: u64_de(versao)?,
            })
        }
        (tipo::ARMAZEM_PROXIMO, [n]) => {
            crate::armazem::fixar_proxima(u64_de(n)?);
            Ok(())
        }
        (tipo::AUDITORIA_LACUNA, [primeira, ultima, elo]) => {
            let l = politica::auditoria::Lacuna {
                primeira: u64_de(primeira)?,
                ultima: u64_de(ultima)?,
                elo: chave(elo)?,
            };
            crate::log_warn!(
                "persistencia",
                "a auditoria perdeu os registros {} a {} antes de grava-los",
                l.primeira,
                l.ultima
            );
            repor_na_auditoria(|c| c.pular(l))
        }
        _ => Err("entrada de registro desconhecida, ou com campos errados"),
    }
}

/// Só para a suíte: põe a persistência num estado, e devolve o anterior.
#[cfg(feature = "modo-teste")]
pub fn forcar_estado_de_teste(novo: Estado) -> Estado {
    com(|p| core::mem::replace(&mut p.estado, novo))
}

/// Só para a suíte: faz a próxima gravação falhar (com `true`), como se o
/// disco ou o TPM tivessem falhado no meio dela.
#[cfg(feature = "modo-teste")]
pub fn falhar_a_proxima_gravacao_de_teste(falhar: bool) {
    FALHAR_A_PROXIMA.store(falhar, Ordering::Release);
}

/// Só para a suíte: o valor do contador da âncora, lido do TPM agora.
#[cfg(feature = "modo-teste")]
pub fn ancora_no_tpm_de_teste() -> Result<u64, &'static str> {
    com_a_ancora(|a, t| a.ler(t, &mut Sorteio)).map_err(|e| e.motivo())
}

/// Só para a suíte: uma entrada de registro de operação, como o journal a
/// grava.
#[cfg(feature = "modo-teste")]
pub fn entrada_de_teste(t: u16, campos: &[&[u8]]) -> Vec<u8> {
    entrada(t, campos).unwrap_or_default()
}

/// Só para a suíte: reaplica um registro, como o boot.
#[cfg(feature = "modo-teste")]
pub fn reaplicar_de_teste(r: &diario::Registro) -> Result<(), &'static str> {
    reaplicar(r)
}

/// Só para a suíte: descarta as entradas anotadas e não gravadas.
#[cfg(feature = "modo-teste")]
pub fn esquecer_pendentes_de_teste() {
    for mut e in tirar_pendentes() {
        politica::sigiloso::zerar_bloco(&mut e);
    }
}

/// Só para a suíte: a senha da âncora, para a escuta do barramento
/// conferir que ela não passa.
#[cfg(feature = "modo-teste")]
pub fn senha_da_ancora_de_teste() -> Option<[u8; 32]> {
    segredos().map(|(_, senha)| senha)
}

#[cfg(feature = "modo-teste")]
static EK_TROCADA: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Só para a suíte: a próxima abertura encontra no journal outra EK
/// fixada que a do TPM — o journal levado para outra máquina.
#[cfg(feature = "modo-teste")]
pub fn trocar_a_ek_fixada_de_teste(trocar: bool) {
    EK_TROCADA.store(trocar, Ordering::Release);
}

/// Só para a suíte: o nascimento da âncora guardado no TPM.
#[cfg(feature = "modo-teste")]
pub fn nascimento_de_teste() -> Result<Option<u64>, &'static str> {
    com_a_ancora(|a, t| a.nascimento(t, INDICE_DO_NASCIMENTO, &mut Sorteio)).map_err(|e| e.motivo())
}

/// Só para a suíte: os bytes dos primeiros `setores` setores da partição de
/// estado, como estão no disco — cifrados.
#[cfg(feature = "modo-teste")]
pub fn bytes_do_journal_de_teste(setores: u64) -> Result<Vec<u8>, &'static str> {
    let mut meio = regiao_atual()?;
    let mut v = alloc::vec![0u8; setores as usize * 512];
    meio.ler(0, &mut v)?;
    Ok(v)
}

/// Só na suíte: a próxima compactação vê o contador do TPM num valor que
/// não é o da base.
#[cfg(feature = "modo-teste")]
static CONTADOR_TROCADO: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "modo-teste")]
pub fn trocar_o_contador_da_proxima_compactacao_de_teste(trocar: bool) {
    CONTADOR_TROCADO.store(trocar, Ordering::Release);
}

/// Só na suíte: o elo que a persistência guarda do último registro da
/// auditoria gravado.
#[cfg(feature = "modo-teste")]
pub fn elo_gravado_de_teste() -> [u8; 32] {
    crate::arch::sem_interrupcoes(|| *ELO_GRAVADO.lock())
}

#[cfg(feature = "modo-teste")]
pub fn auditoria_do_journal_de_teste() -> Result<Cadeia, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = regiao_atual()?;
    let mut c = Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    diario::percorrer(&mut meio, &chave, |r| repor_de_teste(&mut c, &r)).map_err(|e| match e {
        diario::Interrompido::Meio(m) | diario::Interrompido::Recusado { motivo: m, .. } => m,
    })?;
    Ok(c)
}

#[cfg(feature = "modo-teste")]
fn repor_de_teste(c: &mut Cadeia, r: &diario::Registro) -> Result<(), &'static str> {
    for e in entradas(r)? {
        let campos = estado::ler_campos(e)?;
        match campos.as_slice() {
            [t, ev] if *t == tipo::AUDITORIA_EVENTO.to_le_bytes() => {
                let (seq, evento) = politica::auditoria::decodificar(ev)?;
                c.repor(seq, evento)?;
            }
            [t, primeira, ultima, elo]
                if *t == tipo::AUDITORIA_LACUNA.to_le_bytes()
                    || *t == tipo::AUDITORIA_COMPACTADA.to_le_bytes() =>
            {
                c.pular(politica::auditoria::Lacuna {
                    primeira: u64_de(primeira)?,
                    ultima: u64_de(ultima)?,
                    elo: chave(elo)?,
                })?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// A região em que o journal mora, para ler.
#[cfg(feature = "modo-teste")]
fn regiao_atual() -> Result<Particao, &'static str> {
    let [a, b] = regioes()?;
    Ok(if com(|p| p.regiao) == 0 { a } else { b })
}

/// Só para a suíte: encolhe as regiões a `setores` (com `None`, o tamanho
/// inteiro). Vale para a região que a próxima compactação criar; a de
/// agora fica com o tamanho com que foi aberta.
#[cfg(feature = "modo-teste")]
pub fn fixar_limite_de_teste(setores: Option<u64>) {
    LIMITE_DE_TESTE.store(setores.unwrap_or(0), Ordering::Release);
}

/// Só para a suíte: reaplica a região atual inteira, como o boot.
#[cfg(feature = "modo-teste")]
pub fn reaplicar_regiao_de_teste() -> Result<u64, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = regiao_atual()?;
    let p = diario::percorrer(&mut meio, &chave, |r| reaplicar(&r)).map_err(|e| match e {
        diario::Interrompido::Meio(m) | diario::Interrompido::Recusado { motivo: m, .. } => m,
    })?;
    for mut e in tirar_pendentes() {
        politica::sigiloso::zerar_bloco(&mut e);
    }
    Ok(p.quantos)
}

/// Só para a suíte: reaplica só os primeiros `k` registros da região atual
/// — o que um boot reporia se o journal acabasse logo depois do registro
/// `k`, numa queda. Devolve quantos reaplicou.
#[cfg(feature = "modo-teste")]
pub fn reaplicar_prefixo_de_teste(k: u64) -> Result<u64, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = regiao_atual()?;
    let mut feitos = 0u64;
    let r = diario::percorrer(&mut meio, &chave, |r| {
        if feitos >= k {
            return Err(None);
        }
        reaplicar(&r).map_err(Some)?;
        feitos += 1;
        Ok(())
    });
    for mut e in tirar_pendentes() {
        politica::sigiloso::zerar_bloco(&mut e);
    }
    match r {
        Ok(_) | Err(diario::Interrompido::Recusado { motivo: None, .. }) => Ok(feitos),
        Err(diario::Interrompido::Recusado {
            motivo: Some(m), ..
        })
        | Err(diario::Interrompido::Meio(m)) => Err(m),
    }
}

/// Só para a suíte: a região atual percorrida com um byte trocado no setor
/// `alvo`, como um disco que estragou ali. Nada é reaplicado; devolve o
/// percurso — quantos registros abriram, e onde parou.
#[cfg(feature = "modo-teste")]
pub fn percorrer_estragado_de_teste(alvo: u64) -> Result<diario::Percorrido, &'static str> {
    struct Estragado {
        dentro: Particao,
        alvo: u64,
    }
    impl Meio for Estragado {
        fn setores(&self) -> u64 {
            self.dentro.setores()
        }
        fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
            self.dentro.ler(setor, destino)?;
            let fim = setor + (destino.len() / diario::TAM_SETOR) as u64;
            if (setor..fim).contains(&self.alvo) {
                let i = (self.alvo - setor) as usize * diario::TAM_SETOR + 100;
                destino[i] ^= 0x5A;
            }
            Ok(())
        }
        fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
            Err("so leitura")
        }
        fn descarregar(&mut self) -> Result<(), &'static str> {
            Err("so leitura")
        }
    }
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = Estragado {
        dentro: regiao_atual()?,
        alvo,
    };
    diario::percorrer(&mut meio, &chave, |_| Ok::<(), ()>(())).map_err(|_| "a regiao nao se le")
}

/// Só para a suíte: a região atual percorrida, sem reaplicar nada.
#[cfg(feature = "modo-teste")]
pub fn percorrida_atual_de_teste() -> Result<diario::Percorrido, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = regiao_atual()?;
    diario::percorrer(&mut meio, &chave, |_| Ok::<(), ()>(())).map_err(|_| "a regiao nao se le")
}

/// Só para a suíte: a região `i` percorrida, sem reaplicar nada.
#[cfg(feature = "modo-teste")]
pub fn percorrida_de_teste(i: usize) -> Result<diario::Percorrido, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let [a, b] = regioes()?;
    let mut meio = if i == 0 { a } else { b };
    diario::percorrer(&mut meio, &chave, |_| Ok::<(), ()>(())).map_err(|_| "a regiao nao se le")
}

/// Só para a suíte: compacta agora, como o coletor compactaria.
#[cfg(feature = "modo-teste")]
pub fn compactar_de_teste() -> Result<(), &'static str> {
    em_ordem(compactar)
}

/// Só para a suíte: pausa ou solta a compactação do coletor.
#[cfg(feature = "modo-teste")]
pub fn pausar_a_compactacao_de_teste(pausada: bool) {
    COMPACTACAO_PAUSADA.store(pausada, Ordering::Release);
}

/// Só para a suíte: esquece a base que não coube, para o coletor tentar de
/// novo já.
/// Só na suíte: se o boot ou o coletor compactariam agora.
#[cfg(feature = "modo-teste")]
pub fn precisa_compactar_de_teste() -> bool {
    precisa_compactar()
}

#[cfg(feature = "modo-teste")]
pub fn esquecer_o_que_nao_coube_de_teste() {
    NAO_COUBE_EM.store(u64::MAX, Ordering::Release);
}

/// Só para a suíte: grava um registro de `tipo` com `dados`, exigindo a
/// `decisao` nele, pelo caminho de toda gravação.
#[cfg(feature = "modo-teste")]
pub fn gravar_de_teste(tipo: u16, dados: &[u8], decisao: u64) -> Result<(), &'static str> {
    gravar_com_a_decisao(tipo, dados, decisao)
}

/// Só para a suíte: as entradas de um registro, como o boot as lê.
#[cfg(feature = "modo-teste")]
pub fn entradas_de_teste(r: &diario::Registro) -> Result<Vec<&[u8]>, &'static str> {
    entradas(r)
}

/// Só para a suíte: os registros do journal como estão no disco agora —
/// todos, mas o conteúdo só dos últimos [`CONTEUDOS_DE_TESTE`]: o journal
/// da suíte passa do heap do kernel. Os que fixam a EK — a abertura, os de
/// boot, o fecho de uma base — ficam com o conteúdo, que é pequeno.
#[cfg(feature = "modo-teste")]
pub fn ler_de_teste() -> Result<Vec<diario::Registro>, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = regiao_atual()?;
    let mut v: Vec<diario::Registro> = Vec::new();
    diario::percorrer(&mut meio, &chave, |r| {
        if let Some(velho) = v
            .len()
            .checked_sub(CONTEUDOS_DE_TESTE)
            .and_then(|i| v.get_mut(i))
            .filter(|r| !matches!(r.tipo, tipo::ABERTURA | tipo::BOOT | tipo::BASE_FIM))
        {
            politica::sigiloso::zerar_bloco(&mut velho.conteudo);
            velho.conteudo = Vec::new();
        }
        v.push(r);
        Ok::<(), ()>(())
    })
    .map_err(|_| "o journal nao se le")?;
    Ok(v)
}

/// Quantos registros, do fim, [`ler_de_teste`] devolve com o conteúdo.
#[cfg(feature = "modo-teste")]
pub const CONTEUDOS_DE_TESTE: usize = 12;

/// Destrava as trancas da persistência à força, para uso exclusivo do
/// caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        PERSISTENCIA.force_unlock();
        PENDENTES.force_unlock();
        REPOSTA.force_unlock();
        ELO_GRAVADO.force_unlock();
    }
    DONO_DA_ORDEM.store(0, Ordering::Release);
}
