//! A hora do Duke no kernel: o relógio civil, os pedidos e as rodadas do
//! Roughtime, e o fio do serviço de hora.
//!
//! As contas — a moldura, a conferência de uma resposta, o quórum, a
//! disciplina do relógio — moram no pacote `hora`, testadas no hospedeiro.
//! Aqui fica o que o pacote não pode ter:
//!
//! - a régua: o contador do hardware em milissegundos ([`contador`]);
//! - o relógio civil, um só, atrás de uma trava folha ([`civil`]);
//! - os pedidos em aberto e as rodadas de cada principal ([`rodada`]), sob
//!   a vez da hora ([`VEZ`]);
//! - os tratadores que o gate chama: [`pedir`] (`time.request`),
//!   [`entregar`] (`time.sync`) e [`confirmar`] (`time.confirm`, dentro de
//!   `admin.execute`);
//! - o fio `hora` ([`servico`]), que fala só pelo gate.
//!
//! # Os três relógios
//!
//! - **Monotônico** ([`crate::tempo`]): intocado. É a régua dos
//!   arrendamentos, das sessões, das taxas, dos desafios e das esperas, e
//!   nenhuma fonte de hora o ajusta — o serviço só mede a taxa dele contra
//!   a régua ([`contador::mono_ppm`]).
//! - **Civil** ([`civil`]): a melhor estimativa da hora UTC, com incerteza
//!   e estado. Antes do primeiro acordo, o RTC; depois, só o que um acordo
//!   de pelo menos duas chaves do registro prova, aplicado pela disciplina.
//! - **Lógico** ([`crate::persistencia::agora`]): `max(piso, civil em
//!   segundos)`, com o piso no journal. Nunca volta.
//!
//! **Nenhuma decisão de autorização lê o civil nem o lógico**: o gate
//! decide pelo monotônico, e o estado do relógio não concede nada.
//!
//! # Quem move o civil
//!
//! Só dois caminhos, e os dois atrás do gate:
//!
//! - o tratador de `time.sync`, na entrega da última fonte de uma rodada:
//!   o desfecho do quórum vai à disciplina ([`civil::rodada`]);
//! - o tratador de `time.confirm { round }`, uma operação administrativa
//!   com prova: o salto pendente que o acordo da rodada `round` já pediu
//!   ([`civil::confirmar`]) — a rodada só identifica a evidência, e nunca
//!   uma hora digitada.
//!
//! O `xtask` confere que ninguém mais chama os dois.
//!
//! # A auditoria
//!
//! Cada `time.sync` grava, além da decisão do gate, um registro de
//! execução com a fonte e o resumo do pacote entregue (no recurso) e o
//! veredito — aceita com `MIDP`, `RADI` e RTT, ou a recusa e a tentativa
//! (no detalhe). A entrega da última fonte grava também o desfecho da
//! rodada: o civil, o lógico e o estado antes e depois, e as marcas (no
//! recurso); o quórum, o desvio, a incerteza e o efeito (no detalhe). Dois
//! registros, e não um: o detalhe tem teto de 96 bytes no codec, que não
//! muda. Nunca um corpo.

pub mod civil;
pub mod contador;
mod rodada;
pub mod servico;

use alloc::string::String;
use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use hora::disciplina::{Efeito, Estado, Leitura, Parametros};
use hora::quorum::Desfecho;
use hora::registro::Registro;
use hora::resposta::Recusa;
use politica::Codigo;
use protocolo::json::JsonWriter;

use crate::trava::Mutex;

#[cfg(feature = "modo-teste")]
pub use rodada::TETO_DO_RAIO;
pub use rodada::{PRAZO_MS, Resultado};

/// A vez de mexer nos pedidos e nas rodadas: um fio de cada vez.
///
/// Uma trava do fio, como a ordem das gravações do journal
/// (`persistencia::em_ordem`), e não do núcleo: conferir uma resposta custa
/// duas assinaturas Ed25519 — milissegundos no emulador —, e isso não se
/// faz com as interrupções mascaradas. Quem espera cede a CPU. Nunca pedida
/// com uma trava de núcleo na mão; na suíte, a conferência da ordem das
/// travas a vê como uma classe — ver `ordem_das_travas`.
struct Vez<T> {
    /// O fio que tem a vez, como `id + 1`, ou zero.
    dono: AtomicU64,
    dado: UnsafeCell<T>,
}

// SAFETY: o dado só é tocado por quem tem a vez — ver `Vez::com`.
unsafe impl<T: Send> Sync for Vez<T> {}

impl<T> Vez<T> {
    const fn nova(dado: T) -> Self {
        Vez {
            dono: AtomicU64::new(0),
            dado: UnsafeCell::new(dado),
        }
    }

    #[track_caller]
    fn com<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let eu = crate::fios::id_atual() + 1;
        assert!(
            self.dono.load(Ordering::Acquire) != eu,
            "a vez da hora pedida de novo pelo fio que a tem"
        );
        #[cfg(feature = "modo-teste")]
        crate::ordem_das_travas::ao_pedir_a_vez_da_hora();
        while self
            .dono
            .compare_exchange(0, eu, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            debug_assert!(
                crate::arch::interrupcoes_habilitadas(),
                "a vez da hora esperada com as interrupcoes mascaradas"
            );
            crate::fios::ceder();
        }
        // SAFETY: a vez é deste fio até a gravação abaixo, e ninguém toca o
        // dado sem ela.
        let r = f(unsafe { &mut *self.dado.get() });
        self.dono.store(0, Ordering::Release);
        r
    }
}

/// Os pedidos e as rodadas — ver [`rodada`].
static VEZ: Vez<rodada::Tabelas> = Vez::nova(rodada::Tabelas::novas());

/// Se o fio deste núcleo tem a vez da hora, sem tomar trava nenhuma: a
/// conferência da ordem das travas pergunta de dentro de cada `lock`.
#[cfg(feature = "modo-teste")]
pub fn vez_na_mao_sem_trava() -> bool {
    VEZ.dono.load(Ordering::Acquire) == crate::fios::id_atual_sem_trava() + 1
}

/// O nome de uma fonte, guardado por valor: o resumo não guarda o registro.
#[derive(Clone, Copy)]
struct NomeDaFonte {
    bytes: [u8; 32],
    tamanho: u8,
}

impl NomeDaFonte {
    fn de(nome: &str) -> NomeDaFonte {
        let mut bytes = [0u8; 32];
        let tamanho = nome.len().min(bytes.len());
        bytes[..tamanho].copy_from_slice(&nome.as_bytes()[..tamanho]);
        NomeDaFonte {
            bytes,
            tamanho: tamanho as u8,
        }
    }

    fn como_texto(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.tamanho)]).unwrap_or("")
    }
}

/// A última rodada que fechou, como o `system.info` a diz: o desfecho e,
/// de cada fonte do registro dela, o nome e o veredito.
#[derive(Clone, Copy)]
struct UltimaRodada {
    numero: u64,
    do_servico: bool,
    desfecho: Desfecho,
    aceitas: usize,
    fontes: [Option<(NomeDaFonte, &'static str)>; hora::registro::MAIS_FONTES],
}

impl UltimaRodada {
    fn de(f: &rodada::Fechamento) -> UltimaRodada {
        let mut fontes = [None; hora::registro::MAIS_FONTES];
        for (i, fonte) in f.registro().fontes().iter().enumerate() {
            fontes[i] = Some((
                NomeDaFonte::de(fonte.nome()),
                f.fontes()[i].as_ref().map_or("nao_pedida", |v| v.nome()),
            ));
        }
        UltimaRodada {
            numero: f.numero(),
            do_servico: f.principal() == rodada::SERVICO,
            desfecho: f.desfecho,
            aceitas: f.aceitas,
            fontes,
        }
    }
}

/// O que `system.info` diz das rodadas: contagens e a última que fechou.
struct Resumo {
    rodadas: u64,
    com_acordo: u64,
    sem_acordo: u64,
    /// Rodadas que fecharam sem nenhuma resposta aceita.
    perdidas: u64,
    confirmacoes: u64,
    ultima: Option<UltimaRodada>,
    ultimo_efeito: Option<Efeito>,
    /// Quando o civil ficou sincronizado pela primeira vez, no relógio do
    /// kernel.
    primeira_sincronizacao_ms: Option<u64>,
}

static RESUMO: Mutex<Resumo> = Mutex::new(Resumo {
    rodadas: 0,
    com_acordo: 0,
    sem_acordo: 0,
    perdidas: 0,
    confirmacoes: 0,
    ultima: None,
    ultimo_efeito: None,
    primeira_sincronizacao_ms: None,
});

fn com_resumo<R>(f: impl FnOnce(&mut Resumo) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut RESUMO.lock()))
}

/// O custo de conferir uma resposta — as duas assinaturas e o resto —, em
/// ciclos.
pub static CONFERENCIA: crate::metricas::Medida = crate::metricas::Medida::nova();

/// Os parâmetros da disciplina para o registro de agora: os tetos do
/// registro, ou os do desenho sem ele, e a deriva da régua.
fn parametros_da_regua(registro: Option<&Registro>) -> Parametros {
    let p = registro.map_or(Parametros::PADRAO, Registro::parametros);
    Parametros {
        deriva_ppm: contador::deriva_ppm(p.deriva_ppm),
        ..p
    }
}

/// Liga a régua e o civil, com os tetos do registro de fontes: no boot,
/// depois do registro e antes da política e da persistência — o tempo
/// lógico lê o civil desde o primeiro registro da auditoria. Sem registro
/// de fontes, o civil fica no RTC: o comportamento de antes.
pub fn iniciar_civil() {
    contador::iniciar();
    let registro = crate::identidade::fontes_de_hora();
    civil::iniciar(parametros_da_regua(registro.as_deref()));
}

/// Só para a suíte: o civil recomeça no estado `rtc` com os parâmetros do
/// registro de agora — ver [`civil::reiniciar_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn reiniciar_civil_de_teste() {
    let registro = crate::identidade::fontes_de_hora();
    civil::reiniciar_de_teste(parametros_da_regua(registro.as_deref()));
}

/// Só para a suíte: os parâmetros que o civil teria com este registro.
#[cfg(feature = "modo-teste")]
pub fn parametros_de_teste(registro: Option<&Registro>) -> Parametros {
    parametros_da_regua(registro)
}

/// O civil em segundos, para o tempo lógico. Antes de o civil ser ligado —
/// o começo do boot —, o RTC, como sempre foi.
pub fn civil_s() -> Option<u64> {
    if !civil::iniciado() {
        return crate::relogio::agora();
    }
    civil::em_segundos()
}

/// O RTC cru, para o `system.info`: quem lê o RTC é o civil — o `xtask`
/// confere —, e é por ele que o valor cru sai.
pub fn rtc() -> Option<u64> {
    crate::relogio::agora()
}

/// Por que um pedido de hora não foi feito, depois de o gate deixar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A fonte não está no registro — ou não há registro.
    ForaDoRegistro,
    /// A rodada começa pela primeira fonte do registro, e segue a ordem.
    ForaDaOrdem,
    /// A fonte anterior da rodada ainda espera a entrega.
    AnteriorAberta,
    /// A fonte já foi aceita nesta rodada.
    JaAceita,
    /// A tabela de pedidos está cheia, ou o principal no teto dele.
    Cheia,
    /// O kernel não tem fonte de entropia: não há nonce.
    SemEntropia,
    /// Nenhum pedido aberto com este id para quem entrega.
    Desconhecido,
    /// Fora de um comando autorizado.
    SemPrincipal,
}

impl Falha {
    /// O motivo, para a resposta e a auditoria.
    pub fn motivo(self) -> &'static str {
        match self {
            Falha::ForaDoRegistro => "fonte de hora fora do registro",
            Falha::ForaDaOrdem => {
                "fora da ordem da rodada: ela comeca pela primeira fonte do registro e segue a ordem dele"
            }
            Falha::AnteriorAberta => "a fonte anterior da rodada ainda espera a entrega",
            Falha::JaAceita => "esta fonte ja deu uma resposta aceita nesta rodada",
            Falha::Cheia => "a tabela de pedidos de hora esta cheia para este principal",
            Falha::SemEntropia => "o kernel nao tem fonte de entropia: nenhum nonce sai",
            Falha::Desconhecido => "nenhum pedido de hora aberto com este id",
            Falha::SemPrincipal => "fora de um comando autorizado",
        }
    }

    /// O código da resposta.
    pub fn codigo(self) -> &'static str {
        match self {
            Falha::SemEntropia => "ENTROPY_UNAVAILABLE",
            Falha::Cheia => Codigo::DenyQuota.nome(),
            _ => "INVALID_REQUEST",
        }
    }

    /// O código do registro de execução.
    fn na_auditoria(self) -> Codigo {
        match self {
            Falha::SemEntropia => Codigo::Error,
            Falha::Cheia => Codigo::DenyQuota,
            Falha::JaAceita | Falha::AnteriorAberta | Falha::ForaDaOrdem => Codigo::Conflict,
            _ => Codigo::InvalidArgument,
        }
    }
}

/// Um pedido de hora emitido. O pedido, de 1 KiB, em caixa — ver a pilha
/// em [`rodada`].
pub struct PedidoEmitido {
    pub id: u64,
    pub fonte: hora::registro::Fonte,
    pub pedido: alloc::boxed::Box<hora::pedido::Pedido>,
    pub rodada: u64,
}

/// `time.request`: o pedido v1 para a fonte `nome` do registro, ligado ao
/// principal do comando que o gate decidiu. Uma recusa depois do gate fica
/// gravada como execução da decisão.
pub fn pedir(nome: &str) -> Result<PedidoEmitido, Falha> {
    let r = pedir_sem_registro(nome);
    if let Err(f) = r {
        crate::autorizacao::auditar_execucao(nome, f.na_auditoria(), f.motivo());
    }
    r
}

fn pedir_sem_registro(nome: &str) -> Result<PedidoEmitido, Falha> {
    let Some(principal) = crate::autorizacao::principal_decidido() else {
        return Err(Falha::SemPrincipal);
    };
    // O registro, em caixa, vai por referência até a rodada, que guarda a
    // cópia dela.
    let Some(registro) = crate::identidade::fontes_de_hora() else {
        return Err(Falha::ForaDoRegistro);
    };
    let Some((indice, fonte)) = registro.fonte_de_nome(nome).map(|(i, f)| (i, *f)) else {
        return Err(Falha::ForaDoRegistro);
    };
    let mut aleatorio = [0u8; 32];
    if crate::aleatorio::preencher(&mut aleatorio).is_err() {
        return Err(Falha::SemEntropia);
    }
    // A versão lida com a vez na mão: lida antes, ela podia ser de antes de
    // uma troca que outro fio, com a vez, já viu — e largaria as rodadas
    // abertas sob a nova.
    let emitido = VEZ.com(|t| {
        t.pedir(
            principal,
            &registro,
            indice,
            &aleatorio,
            contador::agora_ms(),
            crate::autorizacao::versao_da_politica(),
        )
    });
    match emitido {
        Ok(e) => Ok(PedidoEmitido {
            id: e.id,
            fonte,
            pedido: e.pedido,
            rodada: e.rodada,
        }),
        Err(r) => Err(match r {
            rodada::Recusado::ForaDaOrdem => Falha::ForaDaOrdem,
            rodada::Recusado::AnteriorAberta => Falha::AnteriorAberta,
            rodada::Recusado::JaAceita => Falha::JaAceita,
            rodada::Recusado::Tabela(_) => Falha::Cheia,
            rodada::Recusado::Desconhecido => Falha::Desconhecido,
        }),
    }
}

/// O que uma entrega fez: a fonte, o veredito, e o desfecho da rodada se
/// ela fechou.
pub struct Entregue {
    pub fonte: hora::registro::Fonte,
    pub rodada: u64,
    pub resultado: Resultado,
    pub fechamento: Option<Desfecho>,
    /// O que o civil fez, se a rodada fechou e foi aplicada.
    pub mudanca: Option<civil::Mudanca>,
    /// A rodada fechou mas não foi aplicada: o motivo.
    pub descartada: Option<&'static str>,
}

/// O código de um veredito na auditoria: o que não tem forma de resposta, o
/// que não é desta conversa (o nonce, outro pedido) e o que a chave fixada
/// não assinou se distinguem — a auditoria e o NSF leem a diferença.
fn codigo_da_recusa(r: Recusa) -> Codigo {
    match r {
        Recusa::Nonce | Recusa::OutroPedido => Codigo::DenyReplay,
        Recusa::AssinaturaDaDelegacao | Recusa::AssinaturaDaResposta | Recusa::ForaDaDelegacao => {
            Codigo::DenyCredential
        }
        Recusa::Moldura | Recusa::Estrutura | Recusa::Tipo | Recusa::Versao | Recusa::Raio => {
            Codigo::InvalidArgument
        }
    }
}

/// `time.sync`: a resposta ao pedido `id`, como chegou — ou `None`, o
/// aviso de que ela não veio —, do principal do comando que o gate
/// decidiu. A conferência é contra o registro do pedido, nunca contra o que
/// quem entrega diz. Na última fonte, a rodada fecha: o quórum, a
/// disciplina, o civil.
pub fn entregar(id: u64, pacote: Option<&[u8]>) -> Result<Entregue, Falha> {
    let Some(principal) = crate::autorizacao::principal_decidido() else {
        return Err(Falha::SemPrincipal);
    };
    let deriva = civil::parametros().map_or(Parametros::PADRAO.deriva_ppm, |p| p.deriva_ppm);
    VEZ.com(|t| {
        let agora = contador::agora_ms();
        let inicio = crate::arch::ciclos();
        // A versão com a vez na mão — ver `pedir_sem_registro`.
        let versao = crate::autorizacao::versao_da_politica();
        let entrega = match t.entregar(principal, id, pacote, agora, versao, deriva) {
            Ok(e) => e,
            Err(_) => {
                let f = Falha::Desconhecido;
                crate::autorizacao::auditar_execucao(
                    &alloc::format!("id {id}"),
                    f.na_auditoria(),
                    f.motivo(),
                );
                return Err(f);
            }
        };
        if pacote.is_some() && !matches!(entrega.resultado, Resultado::Vencida) {
            CONFERENCIA.somar(crate::metricas::desde(inicio));
        }
        auditar_o_veredito(&entrega.fonte, pacote, &entrega.resultado);
        let mut entregue = Entregue {
            fonte: entrega.fonte,
            rodada: entrega.rodada,
            resultado: entrega.resultado,
            fechamento: entrega.fechamento.as_ref().map(|f| f.desfecho),
            mudanca: None,
            descartada: None,
        };
        if let Some(f) = entrega.fechamento {
            match aplicar(&f.sem_o_pacote()) {
                Ok(m) => entregue.mudanca = m,
                Err(motivo) => entregue.descartada = Some(motivo),
            }
        }
        Ok(entregue)
    })
}

/// Aplica ao civil uma rodada que fechou, e grava o desfecho. `Err` com o
/// motivo, gravado, se a decisão em curso já não vale — a política mudou
/// no meio: nada da rodada chega ao civil.
fn aplicar(f: &rodada::Fechamento) -> Result<Option<civil::Mudanca>, &'static str> {
    // O ponto de commit: a decisão do gate, refeita pela política de agora
    // (`autorizacao::reconfirmar`), e a rodada aberta sob esta mesma
    // política.
    #[cfg(feature = "modo-teste")]
    crate::autorizacao::gancho_da_reconfirmacao();
    let descarte = if f.versao_da_politica() != crate::autorizacao::versao_da_politica() {
        Some("a politica mudou durante a rodada")
    } else if crate::autorizacao::reconfirmar().is_err() {
        Some("a decisao nao vale mais pela politica de agora")
    } else {
        None
    };
    if let Some(motivo) = descarte {
        crate::autorizacao::auditar_execucao(
            "civil",
            Codigo::DenyPolicy,
            &alloc::format!("r{} descartada: {motivo}", f.numero()),
        );
        return Err(motivo);
    }
    let logico_antes = crate::persistencia::agora();
    let referencia = Some(crate::persistencia::piso().saturating_mul(1000));
    let mudanca = civil::rodada(&f.desfecho, referencia, f.numero());
    let logico_depois = crate::persistencia::agora();
    let uptime = crate::tempo::uptime_ms();
    let ultima = UltimaRodada::de(f);
    com_resumo(|r| {
        r.rodadas += 1;
        match f.desfecho {
            Desfecho::Acordo(_) => r.com_acordo += 1,
            _ => r.sem_acordo += 1,
        }
        if f.aceitas == 0 {
            r.perdidas += 1;
        }
        r.ultima = Some(ultima);
        r.ultimo_efeito = mudanca.map(|m| m.efeito);
        if r.primeira_sincronizacao_ms.is_none()
            && mudanca.is_some_and(|m| m.depois.estado == Estado::Sincronizado)
        {
            r.primeira_sincronizacao_ms = Some(uptime);
        }
    });
    auditar_o_fechamento(f, mudanca.as_ref(), (logico_antes, logico_depois));
    Ok(mudanca)
}

/// O registro de um veredito: a fonte e o resumo do pacote entregue no
/// recurso, o veredito no detalhe.
fn auditar_o_veredito(fonte: &hora::registro::Fonte, pacote: Option<&[u8]>, r: &Resultado) {
    let recurso = match (r, pacote) {
        (Resultado::Aceita { prova, .. }, _) => {
            alloc::format!("{} {}", fonte.nome(), sigilo::hex(&prova.resumo))
        }
        (_, Some(p)) => alloc::format!("{} {}", fonte.nome(), sigilo::hex(&hora::merkle::h(&[p]))),
        (_, None) => String::from(fonte.nome()),
    };
    let (codigo, detalhe) = match r {
        Resultado::Aceita { prova, rtt_ms } => (
            Codigo::Allow,
            alloc::format!(
                "aceita midp {} radi {} rtt {}",
                prova.midp,
                prova.radi,
                rtt_ms
            ),
        ),
        Resultado::Recusada {
            recusa, tentativa, ..
        } => (
            codigo_da_recusa(*recusa),
            alloc::format!(
                "recusada {} {}/{}",
                recusa.nome(),
                tentativa,
                hora::pedidos::MAIS_TENTATIVAS
            ),
        ),
        Resultado::SemResposta => (Codigo::Error, String::from("sem_resposta")),
        Resultado::Vencida => (Codigo::Error, String::from("vencida")),
    };
    crate::autorizacao::auditar_execucao(&recurso, codigo, &detalhe);
}

/// O nome de um efeito, para a auditoria e o `system.info`.
pub fn nome_do_efeito(e: &Efeito) -> &'static str {
    match e {
        Efeito::Nada => "nada",
        Efeito::Gradual { .. } => "gradual",
        Efeito::Candidato { .. } => "candidato",
        Efeito::Salto {
            alem_do_envelope: false,
            ..
        } => "salto",
        Efeito::Salto {
            alem_do_envelope: true,
            ..
        } => "salto_alem",
        Efeito::Pendente { .. } => "pendente",
        Efeito::SemAcordo => "sem_acordo",
    }
}

/// O nome de um desfecho do quórum.
pub fn nome_do_desfecho(d: &Desfecho) -> &'static str {
    match d {
        Desfecho::Acordo(_) => "acordo",
        Desfecho::SemQuorum { .. } => "sem_quorum",
        Desfecho::Empate { .. } => "empate",
        Desfecho::Invalido => "invalido",
    }
}

/// As marcas de uma leitura do civil, com o lógico.
fn marcas(l: &Leitura, logico_s: u64) -> (bool, bool, bool) {
    (
        l.pendente_ms.is_some(),
        l.divergente,
        logico_s > l.meio_ms / 1000,
    )
}

/// O registro do desfecho de uma rodada: o civil, o lógico, o estado e as
/// marcas no recurso; o quórum, o desvio, a incerteza e o efeito no
/// detalhe.
fn auditar_o_fechamento(f: &rodada::Fechamento, m: Option<&civil::Mudanca>, logico: (u64, u64)) {
    let Some(m) = m else {
        crate::autorizacao::auditar_execucao(
            "civil",
            Codigo::Error,
            &alloc::format!("r{} sem relogio civil", f.numero()),
        );
        return;
    };
    let (pendente, divergente, adiantado) = marcas(&m.depois, logico.1);
    let recurso = alloc::format!(
        "civil {}>{} logico {}>{} {}>{}{}{}{}",
        m.antes.meio_ms,
        m.depois.meio_ms,
        logico.0,
        logico.1,
        m.antes.estado.nome(),
        m.depois.estado.nome(),
        if pendente { " pendente" } else { "" },
        if divergente { " divergente" } else { "" },
        if adiantado { " adiantado" } else { "" },
    );
    let mut detalhe = alloc::format!("r{} {}", f.numero(), nome_do_desfecho(&f.desfecho));
    match &f.desfecho {
        Desfecho::Acordo(a) => {
            let desvio = i128::from(a.meio_ms()) - i128::from(m.antes.meio_ms);
            let _ = fmt::write(
                &mut detalhe,
                format_args!(
                    " {}/{} d{:+} u{}",
                    a.cobertura,
                    f.aceitas,
                    desvio,
                    a.incerteza_ms()
                ),
            );
        }
        Desfecho::SemQuorum {
            chaves,
            maior_cobertura,
        } => {
            let _ = fmt::write(&mut detalhe, format_args!(" {maior_cobertura}/{chaves}"));
        }
        Desfecho::Empate { cobertura } => {
            let _ = fmt::write(&mut detalhe, format_args!(" {cobertura}"));
        }
        Desfecho::Invalido => {}
    }
    detalhe.push(' ');
    detalhe.push_str(nome_do_efeito(&m.efeito));
    let codigo = match m.efeito {
        Efeito::Pendente { .. } => Codigo::Conflict,
        Efeito::SemAcordo if m.depois.divergente => Codigo::Conflict,
        Efeito::SemAcordo => Codigo::Error,
        _ => Codigo::Allow,
    };
    crate::autorizacao::auditar_execucao(&recurso, codigo, &detalhe);
}

/// `time.confirm { round }`: aplica o salto pendente da rodada `rodada` —
/// o que o acordo dela pediu, levado até agora pela régua. Chamado só de
/// dentro de `admin.execute`, com a prova e o papel conferidos e a decisão
/// gravada. `Ok` com o recurso do registro da execução: o salto, a rodada,
/// o civil e o lógico antes e depois. `CONFLICT` sem salto pendente, ou
/// com o de outra rodada — a que uma rodada nova pôs no lugar do que quem
/// confirma conferiu —, e então nada se move, nem o civil nem o lógico; o
/// motivo diz a rodada pedida e a do pendente, para o registro.
pub fn confirmar(rodada: u64) -> Result<String, (Codigo, String)> {
    let logico_antes = crate::persistencia::agora();
    let (m, aplicada) = civil::confirmar(rodada).map_err(|recusa| {
        let motivo = match recusa {
            civil::Recusa::SemPendente => String::from("nenhum salto de hora pendente"),
            civil::Recusa::OutraRodada(Some(pendente)) => {
                alloc::format!("r{rodada} nao e a rodada do salto pendente, r{pendente}")
            }
            civil::Recusa::OutraRodada(None) => {
                alloc::format!("r{rodada} nao e a rodada do salto pendente")
            }
        };
        (Codigo::Conflict, motivo)
    })?;
    let logico_depois = crate::persistencia::agora();
    let desvio = match m.efeito {
        Efeito::Salto { desvio_ms, .. } => desvio_ms,
        _ => 0,
    };
    com_resumo(|r| {
        r.confirmacoes += 1;
        r.ultimo_efeito = Some(m.efeito);
    });
    Ok(alloc::format!(
        "salto {:+} r{} civil {}>{} logico {}>{}",
        desvio,
        aplicada,
        m.antes.meio_ms,
        m.depois.meio_ms,
        logico_antes,
        logico_depois
    ))
}

/// O objeto `time` do `system.info`: o civil — meio, incerteza, estado e
/// marcas —, o lógico e quanto ele está adiantado, as fontes em resumo, a
/// régua e a taxa do monotônico. Nenhum nonce, nenhum id, nenhuma resposta:
/// os pedidos são de cada principal, e não aparecem aqui.
pub fn escrever(w: &mut JsonWriter) -> fmt::Result {
    let leitura = civil::ler_com_o_pendente();
    let logico = crate::persistencia::agora();
    w.begin_object()?;
    match leitura {
        Some((l, rodada_do_pendente)) => {
            w.field_str("state", l.estado.nome())?;
            w.field_u64("civil_ms", l.meio_ms)?;
            w.key("uncertainty_ms")?;
            match l.incerteza_ms {
                Some(u) => w.u64_value(u)?,
                None => w.null_value()?,
            }
            w.key("pending_ms")?;
            match l.pendente_ms {
                Some(p) => w.i64_value(p)?,
                None => w.null_value()?,
            }
            // A rodada que pediu o salto: o registro dela na auditoria é a
            // evidência que quem confirma confere antes.
            w.key("pending_round")?;
            match rodada_do_pendente {
                Some(r) => w.u64_value(r)?,
                None => w.null_value()?,
            }
            let (pendente, divergente, adiantado) = marcas(&l, logico);
            w.key("marks")?;
            w.begin_array()?;
            for (nome, tem) in [
                ("pendente", pendente),
                ("divergente", divergente),
                ("adiantado", adiantado),
            ] {
                if tem {
                    w.str_value(nome)?;
                }
            }
            w.end_array()?;
            w.field_bool("beyond_envelope", l.alem_do_envelope)?;
            w.field_u64("logical", logico)?;
            w.field_u64(
                "ahead_ms",
                logico.saturating_mul(1000).saturating_sub(l.meio_ms),
            )?;
        }
        None => {
            w.field_str("state", "desligado")?;
            w.field_u64("logical", logico)?;
        }
    }

    let registro = crate::identidade::fontes_de_hora();
    let (abertos_do_servico, abertos_dos_outros, rodadas_abertas) = VEZ.com(|t| {
        let (s, o) = t.abertos();
        (s, o, t.rodadas_abertas())
    });
    w.key("sources")?;
    w.begin_object()?;
    match &registro {
        Some(r) => {
            w.field_u64("registered", r.fontes().len() as u64)?;
            w.field_u64("quorum", r.quorum())?;
            w.field_bool("moves_clock", r.move_o_relogio())?;
        }
        None => {
            w.field_u64("registered", 0)?;
            w.field_bool("moves_clock", false)?;
        }
    }
    w.end_object()?;

    let (rodadas, com_acordo, sem_acordo, perdidas, confirmacoes, ultima, efeito, primeira) =
        com_resumo(|r| {
            (
                r.rodadas,
                r.com_acordo,
                r.sem_acordo,
                r.perdidas,
                r.confirmacoes,
                r.ultima,
                r.ultimo_efeito,
                r.primeira_sincronizacao_ms,
            )
        });
    w.key("rounds")?;
    w.begin_object()?;
    w.field_u64("closed", rodadas)?;
    w.field_u64("with_agreement", com_acordo)?;
    w.field_u64("without_agreement", sem_acordo)?;
    w.field_u64("lost", perdidas)?;
    w.field_u64("confirmed_jumps", confirmacoes)?;
    w.field_u64("open", rodadas_abertas as u64)?;
    w.field_u64("open_requests_service", abertos_do_servico as u64)?;
    w.field_u64("open_requests_others", abertos_dos_outros as u64)?;
    w.key("last")?;
    match ultima {
        Some(f) => {
            w.begin_object()?;
            w.field_u64("number", f.numero)?;
            w.field_bool("by_service", f.do_servico)?;
            w.field_str("outcome", nome_do_desfecho(&f.desfecho))?;
            if let Desfecho::Acordo(a) = f.desfecho {
                w.field_u64("coverage", a.cobertura as u64)?;
                w.field_u64("uncertainty_ms", a.incerteza_ms())?;
            }
            w.field_u64("accepted", f.aceitas as u64)?;
            if let Some(e) = efeito {
                w.field_str("effect", nome_do_efeito(&e))?;
            }
            w.key("sources")?;
            w.begin_array()?;
            for (nome, veredito) in f.fontes.iter().flatten() {
                w.begin_object()?;
                w.field_str("name", nome.como_texto())?;
                w.field_str("verdict", veredito)?;
                w.end_object()?;
            }
            w.end_array()?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    w.key("first_sync_uptime_ms")?;
    match primeira {
        Some(ms) => w.u64_value(ms)?,
        None => w.null_value()?,
    }
    w.end_object()?;

    w.key("counter")?;
    w.begin_object()?;
    w.field_str("source", contador::origem().nome())?;
    w.field_u64("hz", contador::hz())?;
    w.field_u64("error_ppm", contador::erro_ppm())?;
    w.field_u64("drift_ppm", civil::parametros().map_or(0, |p| p.deriva_ppm))?;
    w.end_object()?;
    w.key("mono_ppm")?;
    match contador::mono_ppm() {
        Some(p) => w.i64_value(p)?,
        None => w.null_value()?,
    }
    let (n, media, maior) = CONFERENCIA.ler();
    w.key("verify_ns")?;
    w.begin_object()?;
    w.field_u64("count", n)?;
    w.field_u64("mean", crate::metricas::nanos(media))?;
    w.field_u64("max", crate::metricas::nanos(maior))?;
    w.end_object()?;
    w.end_object()
}

/// Só para a suíte: larga todas as rodadas e pedidos — um caso começa sem
/// os do anterior.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() {
    VEZ.com(rodada::Tabelas::esvaziar);
}

/// Só para a suíte: os 32 bytes do gerador do último pedido emitido.
#[cfg(feature = "modo-teste")]
pub fn ultimo_aleatorio_de_teste() -> [u8; 32] {
    VEZ.com(|t| t.ultimo_aleatorio)
}

/// Só para a suíte: quantos pedidos estão abertos (do serviço, dos outros)
/// e quantas rodadas.
#[cfg(feature = "modo-teste")]
pub fn abertos_de_teste() -> (usize, usize, usize) {
    VEZ.com(|t| {
        let (s, o) = t.abertos();
        (s, o, t.rodadas_abertas())
    })
}

/// Destrava o resumo, para o caminho de falha fatal — o civil tem o dele,
/// [`civil::destravar`]. A vez da hora é do fio, e não do núcleo: o caminho
/// fatal não a pede.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver `crate::traps::fatal`.
pub unsafe fn destravar() {
    // SAFETY: a garantia de quem chama.
    unsafe { RESUMO.force_unlock() }
}
