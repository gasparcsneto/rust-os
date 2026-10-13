//! O caminho da auditoria: a capacidade que o plano de dados respeita.
//!
//! # O caminho
//!
//! Toda decisão do gate vira um registro no anel da auditoria
//! ([`crate::autorizacao::CAPACIDADE_DA_AUDITORIA`] registros), e o
//! **journal** leva os registros do anel para o disco
//! ([`crate::persistencia`]). Um registro que sai do anel antes de o journal
//! o levar é auditoria perdida: o journal grava uma lacuna no lugar dele.
//!
//! # O atraso
//!
//! O atraso é a distância da cabeça da auditoria ao que o journal já
//! gravou — com a persistência de pé (e, na suíte, sem a gravação
//! periódica pausada). Sem journal, não há o que proteger, e não há
//! contrapressão: a auditoria fica só no anel, como sempre ficou.
//!
//! O tecido de segurança também lê o anel, e não segura ninguém: o gate não
//! sabe que ele existe. O NSF que fica para trás numa inundação se declara
//! degradado, com o atraso dele (`security.status`), como sempre fez.
//!
//! # A contrapressão
//!
//! Só o plano de dados a sente — ver `agent::registry::Plano`: os pedidos
//! sobre um recurso já aberto, que deixaram de gastar a ficha do papel. O
//! exercício de autoridade continua limitado pela taxa do papel, como
//! sempre foi; o fecho de um recurso nunca espera.
//!
//! - Abaixo de [`PARTILHA`]: todos passam.
//! - De [`PARTILHA`] a [`TETO`]: a partilha — passa quem tem, ainda não
//!   consumidos, menos registros de dados que a parte justa
//!   (`PARTILHA / principais com registros pendentes`); quem passou da
//!   parte espera.
//! - De [`TETO`] para cima: todos os pedidos de dados esperam.
//!
//! Esperar é a espera da fase 9.2 ([`crate::rede::espera::Espera`]): o
//! pedido com `wait` não é decidido, não é gravado e não é executado; quem
//! o despachou o guarda, e quando o journal grava, ou o prazo do `wait`
//! vence, **o pedido inteiro passa pelo gate de novo**: identidade,
//! autoridade, política, contenção, firewall e auditoria de agora. Nada
//! aqui recusa um pedido por volume.
//!
//! # A margem
//!
//! De [`TETO`] ao fim do anel há uma quarta parte dele, para o que não
//! espera: a reexecução de quem esperou — uma por pedido suspenso, e os
//! pedidos suspensos são no máximo um por fio, por porta e por console —,
//! o fecho — no máximo um por conexão aberta —, e o exercício de
//! autoridade, que a taxa do papel limita. O pedido de dados **sem**
//! `wait`, com a auditoria cheia, não espera — não pode — nem passa de
//! graça: volta a gastar a ficha do papel, como qualquer pedido, e a taxa
//! grava a primeira recusa e conta as outras.
//!
//! # A partilha não é decisão
//!
//! Este módulo não decide nada sobre ninguém: não recusa, não lê a
//! política, não grava. Diz ao gate se o caminho da auditoria tem lugar
//! para mais um registro de dados deste principal, e acorda quem espera
//! quando ele anda. As contas — quem usou quanto, quem esperou, o atraso —
//! são o que `security.metrics` mostra.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use crate::autorizacao::Principal;
use crate::trava::Mutex;

/// O tamanho do anel da auditoria.
pub const CAPACIDADE: u64 = crate::autorizacao::CAPACIDADE_DA_AUDITORIA as u64;

/// Daqui para cima, a partilha: quem passou da parte justa espera.
pub const PARTILHA: u64 = CAPACIDADE * 5 / 8;

/// Daqui para cima, todo pedido de dados com `wait` espera.
pub const TETO: u64 = CAPACIDADE * 3 / 4;

// A ordem das três, e a margem do teto ao fim do anel: uma quarta parte.
const _: () = assert!(PARTILHA < TETO && TETO < CAPACIDADE);
const _: () = assert!(CAPACIDADE - TETO >= CAPACIDADE / 4);

/// Quantos principais a conta separa. Os seguintes dividem uma linha só,
/// a dos outros — a parte justa deles é a de um.
const PRINCIPAIS: usize = 16;

/// A janela das contas de justiça, em milissegundos: a parte de cada
/// principal nas decisões de dados é medida nesta janela e na anterior.
const JANELA_MS: u64 = 10_000;

/// Quantos wakers de quem espera ficam guardados. Quem espera é uma tarefa
/// — a dos processos, a de cada sessão do canal, o interpretador —, e não
/// cada pedido: são poucas. Passando disso, todos acordam, e conferem.
const MAIS_ESPERANDO: usize = 32;

/// A conta de um principal no plano de dados.
#[derive(Clone, Copy)]
struct Linha {
    principal: Option<Principal>,
    /// Registros de dados dele ainda não consumidos.
    pendentes: u32,
    /// Decisões de dados desde o boot.
    decisoes: u64,
    /// Pedidos dele que esperaram pela auditoria, desde o boot.
    adiados: u64,
    /// Decisões de dados na janela atual e na anterior.
    janela: [u64; 2],
}

impl Linha {
    const VAZIA: Linha = Linha {
        principal: None,
        pendentes: 0,
        decisoes: 0,
        adiados: 0,
        janela: [0; 2],
    };
}

/// A linha dos principais que não couberam na tabela.
const OUTROS: usize = PRINCIPAIS;

/// Os registros de dados ainda não consumidos, em ordem: o número de cada
/// um e a linha do principal. Cabe o anel inteiro: o que passasse disso já
/// teria saído dele.
struct Pendentes {
    seq: [u64; CAPACIDADE as usize],
    linha: [u8; CAPACIDADE as usize],
    inicio: usize,
    tamanho: usize,
}

struct Estado {
    linhas: [Linha; PRINCIPAIS + 1],
    pendentes: Pendentes,
    /// Quem espera: as tarefas que despacharam pedidos adiados.
    esperando: Vec<Waker>,
    janela_desde_ms: u64,
    /// O maior atraso visto desde o boot.
    maior_atraso: u64,
}

static ESTADO: Mutex<Estado> = Mutex::new(Estado {
    linhas: [Linha::VAZIA; PRINCIPAIS + 1],
    pendentes: Pendentes {
        seq: [0; CAPACIDADE as usize],
        linha: [0; CAPACIDADE as usize],
        inicio: 0,
        tamanho: 0,
    },
    esperando: Vec::new(),
    janela_desde_ms: 0,
    maior_atraso: 0,
});

/// Só na suíte: um consumidor simulado, na posição dita — o caso que
/// confere a contrapressão faz de conta que o journal é lento, e o anda
/// quando quer. `u64::MAX` é nenhum.
#[cfg(feature = "modo-teste")]
static CONSUMIDOR_DE_TESTE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Esperas que acabaram, e o tempo delas, para `security.metrics`.
static ESPERAS_ACABADAS: AtomicU64 = AtomicU64::new(0);

/// Até onde o journal levou a auditoria, ou `None` sem journal — ver o
/// cabeçalho. Na suíte, o consumidor simulado, se há um, no lugar dele.
///
/// Fora de qualquer trava deste módulo: o estado da persistência tem a
/// dela.
fn consumo() -> Option<u64> {
    #[cfg(feature = "modo-teste")]
    match CONSUMIDOR_DE_TESTE.load(Ordering::Acquire) {
        u64::MAX => {}
        pos => return Some(pos),
    }
    crate::persistencia::drenando().then(crate::persistencia::auditoria_gravada)
}

/// O atraso, com a cabeça e o consumo ditos: zero sem consumidor.
fn atraso_de(cabeca: u64, consumido: Option<u64>) -> u64 {
    consumido.map_or(0, |c| cabeca.saturating_sub(c))
}

impl Estado {
    /// Tira da conta os registros de dados que o consumo já levou. Sem
    /// consumidor, a conta se esvazia: não há o que proteger, e não se
    /// guarda o que ninguém vai consumir.
    fn andar(&mut self, consumido: Option<u64>) {
        let ate = consumido.unwrap_or(u64::MAX);
        while self.pendentes.tamanho > 0 {
            let i = self.pendentes.inicio;
            if self.pendentes.seq[i] > ate {
                break;
            }
            let l = self.pendentes.linha[i] as usize;
            self.linhas[l].pendentes = self.linhas[l].pendentes.saturating_sub(1);
            self.pendentes.inicio = (i + 1) % CAPACIDADE as usize;
            self.pendentes.tamanho -= 1;
        }
    }

    /// A linha de `p`: a dele, uma livre, a de alguém sem nada pendente, ou
    /// a dos outros.
    fn linha_de(&mut self, p: Principal) -> usize {
        if let Some(i) = self.linhas[..PRINCIPAIS]
            .iter()
            .position(|l| l.principal == Some(p))
        {
            return i;
        }
        let livre = self.linhas[..PRINCIPAIS]
            .iter()
            .position(|l| l.principal.is_none())
            .or_else(|| {
                // Sem livre: a de quem não tem nada pendente e menos usou na
                // janela — a conta dele recomeça se ele voltar.
                (0..PRINCIPAIS)
                    .filter(|&i| self.linhas[i].pendentes == 0)
                    .min_by_key(|&i| self.linhas[i].janela[0] + self.linhas[i].janela[1])
            });
        match livre {
            Some(i) => {
                self.linhas[i] = Linha {
                    principal: Some(p),
                    ..Linha::VAZIA
                };
                i
            }
            None => OUTROS,
        }
    }

    /// Os pendentes de `p`, sem criar linha para ele.
    fn pendentes_de(&self, p: Principal) -> u32 {
        self.linhas[..PRINCIPAIS]
            .iter()
            .find(|l| l.principal == Some(p))
            .map_or(0, |l| l.pendentes)
    }

    /// O caminho tem lugar para mais um registro de dados de `p`, com este
    /// atraso? Ver o cabeçalho.
    fn cabe(&self, p: Principal, atraso: u64) -> bool {
        if atraso < PARTILHA {
            return true;
        }
        if atraso >= TETO {
            return false;
        }
        let deste = self.pendentes_de(p);
        let outros = self
            .linhas
            .iter()
            .filter(|l| l.pendentes > 0 && l.principal != Some(p))
            .count() as u64;
        let parte = PARTILHA / (outros + 1);
        u64::from(deste) < parte
    }

    /// Roda a janela das contas de justiça, se ela venceu.
    fn rodar_janela(&mut self, agora: u64) {
        let passou = agora.saturating_sub(self.janela_desde_ms);
        if passou < JANELA_MS {
            return;
        }
        for l in self.linhas.iter_mut() {
            l.janela[1] = if passou < 2 * JANELA_MS {
                l.janela[0]
            } else {
                0
            };
            l.janela[0] = 0;
        }
        self.janela_desde_ms = agora;
    }
}

/// O caminho da auditoria tem lugar para mais um registro de dados de `p`
/// agora? É a pergunta do gate antes de decidir um pedido de dados — ver
/// o cabeçalho. Não grava nada e não muda a conta de ninguém.
pub fn tem_lugar(p: Principal) -> bool {
    let consumido = consumo();
    let cabeca = crate::autorizacao::ultimo_registro();
    let atraso = atraso_de(cabeca, consumido);
    crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.andar(consumido);
        e.maior_atraso = e.maior_atraso.max(atraso);
        e.cabe(p, atraso)
    })
}

/// O gate adiou um pedido de dados de `p`: a conta da justiça.
pub fn adiou(p: Principal) {
    crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        let i = e.linha_de(p);
        e.linhas[i].adiados += 1;
    });
}

/// O gate gravou a decisão `seq` de um pedido sobre um recurso já aberto
/// de `p` — de dados ou de fecho: o registro entra na conta de `p` até um
/// consumidor levá-lo.
pub fn registrou(p: Principal, seq: u64) {
    if seq == 0 {
        return;
    }
    let consumido = consumo();
    let agora = crate::tempo::uptime_ms();
    crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.rodar_janela(agora);
        e.andar(consumido);
        let i = e.linha_de(p);
        e.linhas[i].decisoes += 1;
        e.linhas[i].janela[0] += 1;
        // Sem consumidor, o registro não espera ninguém.
        if consumido.is_none_or(|c| seq <= c) {
            return;
        }
        // O anel inteiro já está na conta: o mais velho saiu dele, e sai
        // daqui também.
        if e.pendentes.tamanho == CAPACIDADE as usize {
            let velho = e.pendentes.inicio;
            let l = e.pendentes.linha[velho] as usize;
            e.linhas[l].pendentes = e.linhas[l].pendentes.saturating_sub(1);
            e.pendentes.inicio = (velho + 1) % CAPACIDADE as usize;
            e.pendentes.tamanho -= 1;
        }
        let fim = (e.pendentes.inicio + e.pendentes.tamanho) % CAPACIDADE as usize;
        e.pendentes.seq[fim] = seq;
        e.pendentes.linha[fim] = i as u8;
        e.pendentes.tamanho += 1;
        e.linhas[i].pendentes += 1;
    });
}

/// O journal gravou: a conta anda, e quem espera acorda para conferir —
/// fora da trava.
pub fn avancou() {
    let consumido = consumo();
    let acordar = crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.andar(consumido);
        core::mem::take(&mut e.esperando)
    });
    for w in acordar {
        w.wake();
    }
}

/// A espera de `p` pela auditoria acabou? `waker`, se veio um, fica
/// guardado para quando o journal gravar. É a conferência de
/// [`crate::rede::espera::Espera`] para a espera pela auditoria.
///
/// Guardado o waker, o consumo é lido de novo: uma gravação entre a
/// primeira leitura e a guarda — que não achou o waker para acordar — é
/// vista aqui.
pub fn conferir(p: Principal, waker: Option<&Waker>) -> bool {
    if tem_lugar(p) {
        return true;
    }
    let Some(w) = waker else {
        return false;
    };
    let excesso = crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        if !e.esperando.iter().any(|g| g.will_wake(w)) {
            e.esperando.push(w.clone());
        }
        (e.esperando.len() > MAIS_ESPERANDO).then(|| core::mem::take(&mut e.esperando))
    });
    if let Some(todos) = excesso {
        for g in todos {
            g.wake();
        }
    }
    tem_lugar(p)
}

/// Há quem espere pela auditoria? O coletor, então, grava sem esperar o
/// intervalo: é ele quem a faz andar.
pub fn ha_quem_espere() -> bool {
    crate::arch::sem_interrupcoes(|| !ESTADO.lock().esperando.is_empty())
}

/// Uma espera pela auditoria acabou, depois de `ms`.
pub fn esperou(ms: u64) {
    ESPERAS_ACABADAS.fetch_add(1, Ordering::Relaxed);
    crate::metricas::ESPERA_DA_AUDITORIA_MS.somar(ms);
}

/// A conta de um principal, para `security.metrics`.
pub struct ContaDe {
    pub principal: String,
    pub decisoes: u64,
    pub pendentes: u32,
    pub adiados: u64,
    /// Decisões de dados nesta janela e na anterior.
    pub recentes: u64,
}

/// O retrato do caminho, para `security.metrics`.
pub struct Retrato {
    pub cabeca: u64,
    pub atraso: u64,
    pub maior_atraso: u64,
    /// Até onde o journal levou a auditoria, se ele a leva.
    pub journal: Option<u64>,
    pub esperando: usize,
    pub esperas_acabadas: u64,
    pub contas: Vec<ContaDe>,
    /// O índice de Jain das decisões de dados recentes entre os principais
    /// que as fizeram, em milésimos: mil é a partilha igual, e cai quando
    /// um principal toma o caminho para si.
    pub justica_permil: u64,
    /// A maior parte de um principal nas decisões de dados recentes, em
    /// milésimos.
    pub maior_parte_permil: u64,
}

/// O retrato de agora.
pub fn retrato() -> Retrato {
    let consumido = consumo();
    let cabeca = crate::autorizacao::ultimo_registro();
    let agora = crate::tempo::uptime_ms();
    let (linhas, esperando, maior_atraso) = crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.rodar_janela(agora);
        e.andar(consumido);
        (e.linhas, e.esperando.len(), e.maior_atraso)
    });
    let mut contas = Vec::new();
    let (mut soma, mut quadrados, mut ativos, mut maior) = (0u128, 0u128, 0u128, 0u64);
    for (i, l) in linhas.iter().enumerate() {
        let recentes = l.janela[0] + l.janela[1];
        let nome = match (i, l.principal) {
            (OUTROS, _) => String::from("others"),
            (_, Some(p)) => p.texto(),
            (_, None) => continue,
        };
        if recentes > 0 {
            soma += u128::from(recentes);
            quadrados += u128::from(recentes) * u128::from(recentes);
            ativos += 1;
            maior = maior.max(recentes);
        }
        if l.decisoes > 0 || l.adiados > 0 {
            contas.push(ContaDe {
                principal: nome,
                decisoes: l.decisoes,
                pendentes: l.pendentes,
                adiados: l.adiados,
                recentes,
            });
        }
    }
    let justica_permil = match ativos * quadrados {
        0 => 1000,
        d => (soma * soma * 1000 / d) as u64,
    };
    let maior_parte_permil = match soma {
        0 => 0,
        s => (u128::from(maior) * 1000 / s) as u64,
    };
    Retrato {
        cabeca,
        atraso: atraso_de(cabeca, consumido),
        maior_atraso,
        journal: consumido,
        esperando,
        esperas_acabadas: ESPERAS_ACABADAS.load(Ordering::Relaxed),
        contas,
        justica_permil,
        maior_parte_permil,
    }
}

/// Só para a suíte: um consumidor simulado na posição `pos`, ou nenhum, e
/// quem espera acorda para conferir.
#[cfg(feature = "modo-teste")]
pub fn consumidor_de_teste(pos: Option<u64>) {
    CONSUMIDOR_DE_TESTE.store(pos.unwrap_or(u64::MAX), Ordering::Release);
    avancou();
}

/// Só para a suíte: os pendentes de `p` agora.
#[cfg(feature = "modo-teste")]
pub fn pendentes_de_teste(p: Principal) -> u32 {
    let consumido = consumo();
    crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.andar(consumido);
        e.pendentes_de(p)
    })
}

/// Só para a suíte: a conta recomeça — cada caso começa sem os registros
/// de dados dos anteriores e sem consumidor simulado.
#[cfg(feature = "modo-teste")]
pub fn esquecer_de_teste() {
    CONSUMIDOR_DE_TESTE.store(u64::MAX, Ordering::Release);
    crate::arch::sem_interrupcoes(|| {
        let mut e = ESTADO.lock();
        e.linhas = [Linha::VAZIA; PRINCIPAIS + 1];
        e.pendentes.inicio = 0;
        e.pendentes.tamanho = 0;
        e.maior_atraso = 0;
    });
}

/// Destrava o estado à força, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ESTADO.force_unlock();
    }
}
